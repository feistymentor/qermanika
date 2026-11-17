import json
import logging
import threading
import time

import base58
import grpc
from nacl.signing import SigningKey
from prometheus_client import Counter, Gauge

from mm.gen import auth_pb2, auth_pb2_grpc, searcher_pb2, searcher_pb2_grpc, bundle_pb2, packet_pb2

log = logging.getLogger("mm.blockengine")

BUNDLES_SENT = Counter("mm_be_bundles_sent_total", "bundles submitted to block engine")
BUNDLE_RESULTS = Counter("mm_be_bundle_results_total", "bundle results for our bundles", ["outcome"])
BUNDLES_LANDED = Counter("mm_be_bundles_landed_total", "our bundles seen processed or finalized")
INCLUSION_RATIO = Gauge("mm_be_inclusion_ratio", "share of submitted bundles seen on-chain")

LANDED_OUTCOMES = ("processed", "finalized")


class Token:
    def __init__(self, value, expires_at):
        self.value = value
        self.expires_at = expires_at

    def stale(self, margin=75):
        return time.time() + margin >= self.expires_at


class BlockEngine:
    def __init__(self, url, keypair_path, timeout=5.0):
        with open(keypair_path) as f:
            secret = bytes(json.load(f))
        self.signer = SigningKey(secret[:32])
        self.pubkey = bytes(self.signer.verify_key)
        self.pubkey_b58 = base58.b58encode(self.pubkey).decode()
        self.timeout = timeout
        self.channel = grpc.secure_channel(url, grpc.ssl_channel_credentials())
        self.auth = auth_pb2_grpc.AuthServiceStub(self.channel)
        self.searcher = searcher_pb2_grpc.SearcherServiceStub(self.channel)
        self.access = None
        self.refresh = None
        self.auth_lock = threading.Lock()
        self.ours = set()
        self._sent = 0
        self._landed = 0
        self.state_lock = threading.Lock()
        self.stop = threading.Event()
        self.results_thread = None

    def _login(self):
        resp = self.auth.GenerateAuthChallenge(
            auth_pb2.GenerateAuthChallengeRequest(role=auth_pb2.SEARCHER, pubkey=self.pubkey),
            timeout=self.timeout,
        )
        challenge = f"{self.pubkey_b58}-{resp.challenge}"
        sig = self.signer.sign(challenge.encode("utf-8")).signature
        toks = self.auth.GenerateAuthTokens(
            auth_pb2.GenerateAuthTokensRequest(
                challenge=challenge, client_pubkey=self.pubkey, signed_challenge=sig
            ),
            timeout=self.timeout,
        )
        self.access = Token(toks.access_token.value, toks.access_token.expires_at_utc.seconds)
        self.refresh = Token(toks.refresh_token.value, toks.refresh_token.expires_at_utc.seconds)
        log.info("block engine auth ok as %s, access token until %d", self.pubkey_b58, self.access.expires_at)

    def _refresh(self):
        resp = self.auth.RefreshAccessToken(
            auth_pb2.RefreshAccessTokenRequest(refresh_token=self.refresh.value),
            timeout=self.timeout,
        )
        self.access = Token(resp.access_token.value, resp.access_token.expires_at_utc.seconds)
        log.debug("access token refreshed, until %d", self.access.expires_at)

    def _md(self):
        with self.auth_lock:
            if self.access is None or self.refresh.stale():
                self._login()
            elif self.access.stale():
                try:
                    self._refresh()
                except grpc.RpcError as e:
                    log.warning("refresh token rejected: %s; re-authenticating", e.code())
                    self._login()
            return [("authorization", f"Bearer {self.access.value}")]

    def tip_accounts(self):
        resp = self.searcher.GetTipAccounts(
            searcher_pb2.GetTipAccountsRequest(), metadata=self._md(), timeout=self.timeout
        )
        return list(resp.accounts)

    def send_bundle(self, raw_txs):
        packets = [packet_pb2.Packet(data=raw, meta=packet_pb2.Meta(size=len(raw))) for raw in raw_txs]
        req = searcher_pb2.SendBundleRequest(bundle=bundle_pb2.Bundle(packets=packets))
        resp = self.searcher.SendBundle(req, metadata=self._md(), timeout=self.timeout)
        with self.state_lock:
            self.ours.add(resp.uuid)
            self._sent += 1
            self._update_rate()
        BUNDLES_SENT.inc()
        log.info("bundle sent uuid=%s txs=%d", resp.uuid, len(raw_txs))
        return resp.uuid

    def _update_rate(self):
        if self._sent:
            INCLUSION_RATIO.set(self._landed / self._sent)

    def start_results(self):
        self.results_thread = threading.Thread(target=self._results_loop, name="be-results", daemon=True)
        self.results_thread.start()

    def _results_loop(self):
        backoff = 2
        while not self.stop.is_set():
            try:
                stream = self.searcher.SubscribeBundleResults(
                    searcher_pb2.SubscribeBundleResultsRequest(), metadata=self._md()
                )
                log.info("subscribed to bundle results")
                backoff = 2
                for res in stream:
                    if self.stop.is_set():
                        stream.cancel()
                        break
                    self._on_result(res)
                self.stop.wait(backoff)
                backoff = min(backoff + 2, 16)
            except grpc.RpcError as e:
                if self.stop.is_set():
                    break
                log.warning("SubscribeBundleResults: %s", e.details())
                self.stop.wait(backoff)
                backoff = min(backoff + 2, 16)

    def _on_result(self, res):
        outcome = res.WhichOneof("result")
        with self.state_lock:
            if res.bundle_id not in self.ours:
                return
            BUNDLE_RESULTS.labels(outcome=outcome or "unknown").inc()
            if outcome in LANDED_OUTCOMES:
                self.ours.discard(res.bundle_id)
                self._landed += 1
                BUNDLES_LANDED.inc()
                self._update_rate()
        if outcome in ("rejected", "dropped"):
            log.info("bundle %s %s: %s", res.bundle_id, outcome, getattr(res, outcome))
        else:
            log.debug("bundle %s %s", res.bundle_id, outcome)

    def land_rate(self):
        with self.state_lock:
            return self._landed / self._sent if self._sent else 0.0

    def close(self):
        self.stop.set()
        self.channel.close()
        if self.results_thread:
            self.results_thread.join(timeout=5)
