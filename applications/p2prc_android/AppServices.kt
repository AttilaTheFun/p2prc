// The Android host half of Convo: the app-specific dependency injection for
// the compiled cell. isomer ships no services — only the generic DI
// pattern; this file owns the Convo ones, installed into the swift_ffi
// dependency dictionary through the generated `installConvoHost` export
// before the runtime starts. Completions return through the app's
// `convoRequestComplete` export, delivered on the runtime's driving thread.
//
// The transport is real libwebrtc (io.github.webrtc-sdk:android), mirroring
// the browser host in applications/p2prc_web/index.html method for method:
// the same one-connection-per-peer map, the same "z"+base64url(gzip(slim))
// blob encoding, the same wait-for-ICE-then-read-localDescription flow, the
// same event strings. QR draw/scan are still stubbed — joining rides an
// invite link (VIEW intent → openingHash), the same auto-pair path a
// browser uses.

package dev.isomer.runtime

import android.app.Activity
import android.content.Context
import android.util.Base64
import android.os.Looper
import android.os.Handler
import android.net.Uri
import android.graphics.BitmapFactory
import android.content.Intent
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.ByteBuffer
import java.util.zip.GZIPInputStream
import java.util.zip.GZIPOutputStream
import kotlin.concurrent.thread
import org.json.JSONArray
import org.webrtc.AudioSource
import org.webrtc.AudioTrack
import org.webrtc.DataChannel
import org.webrtc.IceCandidate
import org.webrtc.MediaConstraints
import org.webrtc.MediaStream
import org.webrtc.PeerConnection
import org.webrtc.PeerConnectionFactory
import org.webrtc.RtpSender
import org.webrtc.SdpObserver
import org.webrtc.SessionDescription
import org.webrtc.audio.JavaAudioDeviceModule

object ConvoAndroidServices {
    private const val TAG = "Convo"

    // --- Completion / event plumbing -------------------------------------
    // Everything crossing back into Swift goes through the runtime's driving
    // thread; WebRTC callbacks arrive on libwebrtc's signaling thread.

    private fun complete(requestID: Int, ok: Boolean, payload: String) {
        NativeBridge.deliverToRuntime {
            SwiftUIBridge.convoRequestComplete(requestID, ok, payload)
        }
    }

    private fun emit(kind: String, payload: String) {
        NativeBridge.deliverToRuntime {
            SwiftUIBridge.convoEvent(kind, payload)
        }
    }

    // --- Compact blob encoding (byte-compatible with the other hosts) ----

    private fun b64url(bytes: ByteArray): String =
        android.util.Base64.encodeToString(
            bytes,
            android.util.Base64.URL_SAFE or android.util.Base64.NO_PADDING or android.util.Base64.NO_WRAP
        )

    private fun unb64url(text: String): ByteArray {
        var s = text
        while (s.length % 4 != 0) s += "="
        return android.util.Base64.decode(s, android.util.Base64.URL_SAFE)
    }

    /// Trims SDP to what a data channel needs — smaller QR, easier scan. The
    /// trailing CRLF is required: without it the last attribute is
    /// unterminated and strict parsers reject the whole description.

    // --- WebRTC ------------------------------------------------------------

    private var factory: PeerConnectionFactory? = null
    private val handler = android.os.Handler(android.os.Looper.getMainLooper())
    private data class IceEntry(val urls: List<String>, val username: String?, val credential: String?)
    private var iceServers = listOf(IceEntry(listOf("stun:stun.l.google.com:19302"), null, null))

    private class Entry(val pc: PeerConnection) {
        var channel: DataChannel? = null
        var audioSource: AudioSource? = null
        var audioTrack: AudioTrack? = null
        val audioSenders = mutableListOf<RtpSender>()
        val gatherWaiters = mutableListOf<Runnable>()
    }

    private val conns = HashMap<String, Entry>()

    private fun requireFactory(app: Context): PeerConnectionFactory {
        factory?.let { return it }
        PeerConnectionFactory.initialize(
            PeerConnectionFactory.InitializationOptions.builder(app)
                .createInitializationOptions()
        )
        val built = PeerConnectionFactory.builder()
            .setAudioDeviceModule(JavaAudioDeviceModule.builder(app).createAudioDeviceModule())
            .createPeerConnectionFactory()
        factory = built
        return built
    }

    private fun rtcConfig(): PeerConnection.RTCConfiguration {
        val servers = iceServers.map { entry ->
            val builder = PeerConnection.IceServer.builder(entry.urls)
            if (entry.username != null && entry.credential != null) {
                builder.setUsername(entry.username).setPassword(entry.credential)
            }
            builder.createIceServer()
        }
        val config = PeerConnection.RTCConfiguration(servers)
        config.sdpSemantics = PeerConnection.SdpSemantics.UNIFIED_PLAN
        // Test knob: `adb shell setprop debug.convo.relay_only 1` forces every
        // candidate through TURN, which is how a relay gets proven end to end
        // on a LAN that would otherwise connect directly.
        if (relayOnly()) config.iceTransportsType = PeerConnection.IceTransportsType.RELAY
        android.util.Log.i(TAG, "pc config: " + servers.size + " ice server(s), relayOnly=" + relayOnly())
        return config
    }

    private fun relayOnly(): Boolean = try {
        val get = Class.forName("android.os.SystemProperties").getMethod("get", String::class.java)
        (get.invoke(null, "debug.convo.relay_only") as? String) == "1"
    } catch (_: Exception) { false }

    private fun closeEntry(peer: String) {
        val entry = synchronized(conns) { conns.remove(peer) } ?: return
        entry.audioTrack?.setEnabled(false)
        try { entry.channel?.close() } catch (_: Exception) {}
        try { entry.pc.close() } catch (_: Exception) {}
        entry.audioTrack?.dispose()
        entry.audioSource?.dispose()
    }

    private fun wire(peer: String, dc: DataChannel) {
        val entry = synchronized(conns) { conns[peer] } ?: return
        entry.channel = dc
        dc.registerObserver(object : DataChannel.Observer {
            override fun onBufferedAmountChange(previousAmount: Long) {}
            override fun onStateChange() {
                when (dc.state()) {
                    DataChannel.State.OPEN -> emit("open", peer)
                    DataChannel.State.CLOSED -> emit("state", "$peer disconnected")
                    else -> {}
                }
            }
            override fun onMessage(buffer: DataChannel.Buffer) {
                val bytes = ByteArray(buffer.data.remaining())
                buffer.data.get(bytes)
                emit("frame", peer + " " + android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP))
            }
        })
        // A channel handed over by onDataChannel can already be open, in
        // which case onStateChange never fires for OPEN.
        if (dc.state() == DataChannel.State.OPEN) emit("open", peer)
    }

    private fun newConnection(app: Context, peer: String): Entry {
        closeEntry(peer)
        val pc = requireFactory(app).createPeerConnection(
            rtcConfig(),
            object : PeerConnection.Observer {
                override fun onSignalingChange(state: PeerConnection.SignalingState) {}
                override fun onIceConnectionChange(state: PeerConnection.IceConnectionState) {}
                override fun onIceConnectionReceivingChange(receiving: Boolean) {}
                override fun onIceGatheringChange(state: PeerConnection.IceGatheringState) {
                    if (state != PeerConnection.IceGatheringState.COMPLETE) return
                    val entry = synchronized(conns) { conns[peer] } ?: return
                    val waiters = synchronized(entry.gatherWaiters) {
                        val copy = entry.gatherWaiters.toList()
                        entry.gatherWaiters.clear()
                        copy
                    }
                    waiters.forEach { it.run() }
                }
                override fun onIceCandidate(candidate: IceCandidate) {
                    android.util.Log.i(TAG, "pc[" + peer + "] candidate " + candidate.sdp.substringAfter("typ ").substringBefore(" "))
                }
                override fun onIceCandidatesRemoved(candidates: Array<out IceCandidate>) {}
                override fun onAddStream(stream: MediaStream) {}
                override fun onRemoveStream(stream: MediaStream) {}
                override fun onDataChannel(channel: DataChannel) { wire(peer, channel) }
                override fun onRenegotiationNeeded() {}
                override fun onConnectionChange(state: PeerConnection.PeerConnectionState) {
                    android.util.Log.i(TAG, "pc[" + peer + "] -> " + state.name)
                    emit("state", peer + " " + state.name.lowercase())
                }
                // Remote audio plays through the audio device module on its
                // own; nothing to wire here.
            }
        ) ?: throw IllegalStateException("createPeerConnection returned null")
        val entry = Entry(pc)
        synchronized(conns) { conns[peer] = entry }
        return entry
    }

    /// Runs `then` once ICE gathering completes, capped at 3s so a candidate
    /// that never arrives doesn't hang the ceremony (same cap as the other
    /// hosts). The local description is what gathering fills in, so callers
    /// read it only after this.
    private fun awaitGathered(entry: Entry, then: () -> Unit) {
        if (entry.pc.iceGatheringState() == PeerConnection.IceGatheringState.COMPLETE) {
            then(); return
        }
        val fired = java.util.concurrent.atomic.AtomicBoolean(false)
        val once = Runnable { if (fired.compareAndSet(false, true)) then() }
        synchronized(entry.gatherWaiters) { entry.gatherWaiters.add(once) }
        handler.postDelayed(once, 3000)
    }

    // Small adapters so the SDP dance reads like the JS it mirrors.
    private fun sdpCreate(
        run: (SdpObserver, MediaConstraints) -> Unit,
        onFail: (String) -> Unit,
        onDone: (SessionDescription) -> Unit,
    ) {
        run(object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) = onDone(sdp)
            override fun onCreateFailure(error: String?) = onFail(error ?: "createFailure")
            override fun onSetSuccess() {}
            override fun onSetFailure(error: String?) {}
        }, MediaConstraints())
    }

    private fun sdpSet(
        run: (SdpObserver) -> Unit,
        onFail: (String) -> Unit,
        onDone: () -> Unit,
    ) {
        run(object : SdpObserver {
            override fun onCreateSuccess(sdp: SessionDescription) {}
            override fun onCreateFailure(error: String?) {}
            override fun onSetSuccess() = onDone()
            override fun onSetFailure(error: String?) = onFail(error ?: "setFailure")
        })
    }

    private fun addLocalAudio(entry: Entry) {
        if (entry.audioTrack != null) return
        val f = factory ?: return
        val source = f.createAudioSource(MediaConstraints())
        val track = f.createAudioTrack("convo-audio", source)
        entry.audioSource = source
        entry.audioTrack = track
        entry.audioSenders.add(entry.pc.addTrack(track, listOf("convo-stream")))
    }

    // --- Serving helpers ---------------------------------------------------

    /// Copies the bundled web site out of assets/ (not a filesystem path)
    /// into filesDir/site once, so the Swift server can read files.
    // --- Installation -------------------------------------------------------

    private var appContext: Context? = null

    /// Seed signaling servers, comma-separated.
    private const val SEEDS = "https://node-1.p2prc.org,https://node-2.p2prc.org,https://node-3.p2prc.org"

    fun install(context: Context) {
        val app = context.applicationContext
        appContext = app
        val activity = context as? Activity
        val prefs = app.getSharedPreferences("convo", Context.MODE_PRIVATE)

        SwiftUIBridge.installConvoHost(object : ConvoHost {
            // MARK: transport
            override fun createOffer(requestID: Int, peer: String) {
                try {
                    val entry = newConnection(app, peer)
                    wire(peer, entry.pc.createDataChannel("convo", DataChannel.Init().apply { ordered = true }))
                    sdpCreate({ o, c -> entry.pc.createOffer(o, c) }, { complete(requestID, false, it) }) { offer ->
                        sdpSet({ o -> entry.pc.setLocalDescription(o, offer) }, { complete(requestID, false, it) }) {
                            awaitGathered(entry) {
                                val sdp = entry.pc.localDescription?.description ?: offer.description
                                complete(requestID, true, sdp)
                            }
                        }
                    }
                } catch (error: Exception) {
                    complete(requestID, false, error.message ?: "createOffer failed")
                }
            }

            override fun acceptOffer(requestID: Int, peer: String, blob: String) {
                try {
                    val entry = newConnection(app, peer)
                    val remote = SessionDescription(SessionDescription.Type.OFFER, blob)
                    sdpSet({ o -> entry.pc.setRemoteDescription(o, remote) }, { complete(requestID, false, it) }) {
                        sdpCreate({ o, c -> entry.pc.createAnswer(o, c) }, { complete(requestID, false, it) }) { answer ->
                            sdpSet({ o -> entry.pc.setLocalDescription(o, answer) }, { complete(requestID, false, it) }) {
                                awaitGathered(entry) {
                                    val sdp = entry.pc.localDescription?.description ?: answer.description
                                    complete(requestID, true, sdp)
                                }
                            }
                        }
                    }
                } catch (error: Exception) {
                    complete(requestID, false, error.message ?: "acceptOffer failed")
                }
            }

            override fun acceptAnswer(requestID: Int, peer: String, blob: String) {
                try {
                    val entry = synchronized(conns) { conns[peer] }
                    if (entry == null) { complete(requestID, false, "no connection"); return }
                    val remote = SessionDescription(SessionDescription.Type.ANSWER, blob)
                    sdpSet({ o -> entry.pc.setRemoteDescription(o, remote) }, {
                        android.util.Log.w(TAG, "acceptAnswer setRemote failed: " + it)
                        emit("error", it)
                    }) {
                        android.util.Log.i(TAG, "acceptAnswer applied for " + peer)
                        complete(requestID, true, "")
                    }
                } catch (error: Exception) {
                    emit("error", error.message ?: "acceptAnswer failed")
                }
            }

            override fun sendFrame(peer: String, text: String) {
                val channel = synchronized(conns) { conns[peer] }?.channel ?: return
                if (channel.state() != DataChannel.State.OPEN) return
                val bytes = android.util.Base64.decode(text, android.util.Base64.NO_WRAP)
                channel.send(DataChannel.Buffer(ByteBuffer.wrap(bytes), true))
            }

            override fun closeConnection(peer: String) = closeEntry(peer)

            override fun setIceServers(json: String) {
                try {
                    // Entries are { urls, username?, credential? }: STUN bare,
                    // TURN with the credentials a relay minted for us.
                    val parsed = JSONArray(json)
                    val entries = (0 until parsed.length()).map { i ->
                        val entry = parsed.getJSONObject(i)
                        val urls = entry.getJSONArray("urls")
                        IceEntry(
                            (0 until urls.length()).map { urls.getString(it) },
                            entry.optString("username", "").ifEmpty { null },
                            entry.optString("credential", "").ifEmpty { null }
                        )
                    }
                    if (entries.isNotEmpty()) iceServers = entries
                    android.util.Log.i(TAG, "ice servers: " + entries.joinToString { it.urls.joinToString() + (if (it.username != null) " (auth)" else "") })
                } catch (error: Exception) {
                    android.util.Log.w(TAG, "ice servers: unparseable", error)
                }
            }

            // MARK: calls — audio on the same pc, renegotiated over the
            // channel. Raw SDP both ways (it rides the encrypted channel,
            // not a QR, so it needs no packing).
            // `video` is accepted and ignored: Android calls are audio until
            // the camera and a renderer are wired (TODO.md).
            override fun callStart(requestID: Int, peer: String, video: Boolean) {
                try {
                    val entry = synchronized(conns) { conns[peer] }
                    if (entry == null) { complete(requestID, false, ""); return }
                    addLocalAudio(entry)
                    sdpCreate({ o, c -> entry.pc.createOffer(o, c) }, { complete(requestID, false, "") }) { offer ->
                        sdpSet({ o -> entry.pc.setLocalDescription(o, offer) }, { complete(requestID, false, "") }) {
                            awaitGathered(entry) {
                                complete(requestID, true, entry.pc.localDescription?.description ?: offer.description)
                            }
                        }
                    }
                } catch (error: Exception) {
                    complete(requestID, false, "")
                }
            }

            override fun callApplyRemote(requestID: Int, peer: String, sdp: String, isOffer: Boolean, video: Boolean) {
                try {
                    val entry = synchronized(conns) { conns[peer] }
                    if (entry == null) { complete(requestID, false, ""); return }
                    if (isOffer) addLocalAudio(entry)
                    val type = if (isOffer) SessionDescription.Type.OFFER else SessionDescription.Type.ANSWER
                    sdpSet({ o -> entry.pc.setRemoteDescription(o, SessionDescription(type, sdp)) }, { complete(requestID, false, "") }) {
                        if (!isOffer) { complete(requestID, true, ""); return@sdpSet }
                        sdpCreate({ o, c -> entry.pc.createAnswer(o, c) }, { complete(requestID, false, "") }) { answer ->
                            sdpSet({ o -> entry.pc.setLocalDescription(o, answer) }, { complete(requestID, false, "") }) {
                                awaitGathered(entry) {
                                    complete(requestID, true, entry.pc.localDescription?.description ?: answer.description)
                                }
                            }
                        }
                    }
                } catch (error: Exception) {
                    complete(requestID, false, "")
                }
            }

            override fun callEnd(peer: String) {
                val entry = synchronized(conns) { conns[peer] } ?: return
                entry.audioTrack?.setEnabled(false)
                for (sender in entry.audioSenders) {
                    try { entry.pc.removeTrack(sender) } catch (_: Exception) {}
                }
                entry.audioSenders.clear()
                entry.audioTrack?.dispose()
                entry.audioSource?.dispose()
                entry.audioTrack = null
                entry.audioSource = null
            }

            // MARK: persistence
            override fun save(key: String, value: String) {
                prefs.edit().putString(key, value).apply()
            }
            override fun load(requestID: Int, key: String) =
                complete(requestID, true, prefs.getString(key, "") ?: "")
            // Secrets: a private preferences file whose values are sealed
            // under an AES-GCM key that lives in the Android Keystore (never
            // leaves the hardware-backed store on devices that have one); a
            // value written in the clear by an earlier build is sealed on
            // first read.
            override fun saveSecret(key: String, value: String) {
                val secrets = app.getSharedPreferences("convo_secrets", Context.MODE_PRIVATE)
                if (value.isEmpty()) secrets.edit().remove(key).apply()
                else secrets.edit().putString(key, SecretBox.seal(value)).apply()
            }
            override fun loadSecret(requestID: Int, key: String) {
                val secrets = app.getSharedPreferences("convo_secrets", Context.MODE_PRIVATE)
                val stored = secrets.getString(key, "") ?: ""
                val value = SecretBox.open(stored)
                if (stored.isNotEmpty() && !stored.startsWith(SecretBox.PREFIX)) secrets.edit().putString(key, SecretBox.seal(value)).apply()
                complete(requestID, true, value)
            }

            // MARK: page identity — an app, not a page. The fragment of a
            // VIEW-intent launch is the opening hash, so an invite link
            // auto-pairs exactly like a browser opening it.
            override fun pageURL(requestID: Int) = complete(requestID, true, "")
            override fun openingHash(requestID: Int) =
                complete(requestID, true, activity?.intent?.data?.fragment ?: "")
            override fun setHash(value: String) {}

            // MARK: QR — drawing is a no-op until an Android QR pane exists;
            // scanning reports failure and the guest shows its fallback.
            override fun drawQR(elementID: String, text: String) {}
            // The code as a PNG in the cache dir, ten pixels a module with the
            // standard four-module quiet zone, handed to the UI as a file URL.
            override fun qrImage(requestID: Int, text: String) {
                thread(name = "convo-qr") {
                    val url = try {
                        val hints = mapOf(com.google.zxing.EncodeHintType.MARGIN to 4,
                                          com.google.zxing.EncodeHintType.ERROR_CORRECTION to com.google.zxing.qrcode.decoder.ErrorCorrectionLevel.L)
                        val modules = com.google.zxing.qrcode.QRCodeWriter().encode(text, com.google.zxing.BarcodeFormat.QR_CODE, 0, 0, hints)
                        val scale = 10
                        val size = modules.width * scale
                        val pixels = IntArray(size * size)
                        for (y in 0 until size) for (x in 0 until size) {
                            pixels[y * size + x] = if (modules.get(x / scale, y / scale)) android.graphics.Color.BLACK else android.graphics.Color.WHITE
                        }
                        val bitmap = android.graphics.Bitmap.createBitmap(pixels, size, size, android.graphics.Bitmap.Config.ARGB_8888)
                        val file = java.io.File(app.cacheDir, "convo-qr-" + Integer.toHexString(text.hashCode()) + ".png")
                        file.outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
                        "file://" + file.absolutePath
                    } catch (error: Exception) {
                        android.util.Log.w(TAG, "qrImage failed", error); ""
                    }
                    Handler(Looper.getMainLooper()).post { complete(requestID, url.isNotEmpty(), url) }
                }
            }
            override fun saveQR(elementID: String) {}
            // A live camera over the app that reads the first QR code it
            // sees and closes (QRScanner below).
            override fun scanQR(requestID: Int) {
                val host = activity as? androidx.activity.ComponentActivity
                if (host == null) { complete(requestID, false, ""); return }
                QRScanner.scan(host) { code -> complete(requestID, code != null, code ?: "") }
            }

            override fun copyText(text: String) {
                val clipboard = app.getSystemService(Context.CLIPBOARD_SERVICE) as android.content.ClipboardManager
                clipboard.setPrimaryClip(android.content.ClipData.newPlainText("Recovery phrase", text))
            }

            override fun share(text: String) {
                val send = Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, text)
                }
                app.startActivity(Intent.createChooser(send, null).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                })
            }

            // MARK: networking stack
            // No QR scanner yet: joining rides an invite link.
            override fun capabilities(requestID: Int) = complete(requestID, true, """{"scansQR":true,"picksImages":true}""")

            // The system image chooser through isomer's picker host
            // (registered on the activity at creation), downscaled to a
            // JPEG in the cache dir; answered as "<mime>|<width>|<height>|<base64>".
            override fun pickImage(requestID: Int) {
                ImagePickerHost.pick(1600) { url ->
                    if (url.isEmpty()) { complete(requestID, false, ""); return@pick }
                    thread(name = "convo-pick") {
                        val answer = try {
                            val file = java.io.File(Uri.parse(url).path ?: "")
                            val bytes = file.readBytes()
                            val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, bounds)
                            file.delete()
                            "image/jpeg|${bounds.outWidth}|${bounds.outHeight}|" + Base64.encodeToString(bytes, Base64.NO_WRAP)
                        } catch (error: Exception) { "" }
                        Handler(Looper.getMainLooper()).post { complete(requestID, answer.isNotEmpty(), answer) }
                    }
                }
            }

            override fun imageURL(requestID: Int, key: String, bytes64: String, mime: String) {
                try {
                    val file = java.io.File(context.cacheDir, "convo-img-$key." + (if (mime == "image/png") "png" else "jpg"))
                    if (!file.exists()) file.writeBytes(android.util.Base64.decode(bytes64, android.util.Base64.DEFAULT))
                    complete(requestID, true, "file://" + file.absolutePath)
                } catch (error: Exception) {
                    android.util.Log.w(TAG, "imageURL failed", error)
                    complete(requestID, false, "")
                }
            }

            // Seed signaling servers (docs/architecture.md §4): configuration
            // the client health-checks like any other server.
            override fun seeds(requestID: Int) = complete(requestID, true, SEEDS)

            override fun httpGet(requestID: Int, url: String) {
                thread(name = "convo-get") {
                    var ok = false
                    var body = ""
                    try {
                        val connection = URL(url).openConnection() as HttpURLConnection
                        connection.connectTimeout = 15000
                        connection.readTimeout = 15000
                        connection.instanceFollowRedirects = true
                        if (connection.responseCode in 200..299) {
                            body = connection.inputStream.bufferedReader().use { it.readText() }
                            ok = true
                        }
                    } catch (error: Exception) {
                        android.util.Log.w(TAG, "httpGet failed: $url", error)
                    }
                    complete(requestID, ok, body)
                }
            }

            override fun httpPost(requestID: Int, url: String, body: String) {
                thread(name = "convo-post") {
                    var ok = false
                    var text = ""
                    try {
                        val connection = URL(url).openConnection() as HttpURLConnection
                        connection.connectTimeout = 15000
                        connection.readTimeout = 15000
                        connection.requestMethod = "POST"
                        connection.doOutput = true
                        connection.setRequestProperty(
                            "Content-Type", if (body.startsWith("{")) "application/json" else "text/plain"
                        )
                        connection.outputStream.use { it.write(body.toByteArray()) }
                        if (connection.responseCode in 200..299) {
                            text = connection.inputStream.bufferedReader().use { it.readText() }
                            ok = true
                        }
                    } catch (error: Exception) {
                        android.util.Log.w(TAG, "httpPost failed: $url", error)
                    }
                    complete(requestID, ok, text)
                }
            }

            override fun httpGetBytesSigned(requestID: Int, url: String, auth: String) {
                thread(name = "convo-get") {
                    var ok = false
                    var body = ""
                    try {
                        val connection = URL(url).openConnection() as HttpURLConnection
                        connection.connectTimeout = 15000
                        connection.readTimeout = 15000
                        connection.setRequestProperty("X-Convo-Auth", auth)
                        if (connection.responseCode in 200..299) {
                            body = android.util.Base64.encodeToString(connection.inputStream.use { it.readBytes() }, android.util.Base64.NO_WRAP)
                            ok = true
                        }
                    } catch (error: Exception) {
                        android.util.Log.w(TAG, "httpGetBytesSigned failed: $url", error)
                    }
                    complete(requestID, ok, body)
                }
            }

            override fun httpGetBytes(requestID: Int, url: String) {
                thread(name = "convo-get") {
                    var ok = false
                    var body = ""
                    try {
                        val connection = URL(url).openConnection() as HttpURLConnection
                        connection.connectTimeout = 15000
                        connection.readTimeout = 15000
                        if (connection.responseCode in 200..299) {
                            body = android.util.Base64.encodeToString(connection.inputStream.use { it.readBytes() }, android.util.Base64.NO_WRAP)
                            ok = true
                        }
                    } catch (error: Exception) {
                        android.util.Log.w(TAG, "httpGetBytes failed: $url", error)
                    }
                    complete(requestID, ok, body)
                }
            }

            override fun httpPostBytes(requestID: Int, url: String, body64: String) {
                thread(name = "convo-post") {
                    var ok = false
                    var text = ""
                    try {
                        val connection = URL(url).openConnection() as HttpURLConnection
                        connection.connectTimeout = 15000
                        connection.readTimeout = 15000
                        connection.requestMethod = "POST"
                        connection.doOutput = true
                        connection.setRequestProperty("Content-Type", "application/octet-stream")
                        connection.outputStream.use { it.write(android.util.Base64.decode(body64, android.util.Base64.NO_WRAP)) }
                        if (connection.responseCode in 200..299) {
                            text = android.util.Base64.encodeToString(connection.inputStream.use { it.readBytes() }, android.util.Base64.NO_WRAP)
                            ok = true
                        }
                    } catch (error: Exception) {
                        android.util.Log.w(TAG, "httpPostBytes failed: $url", error)
                    }
                    complete(requestID, ok, text)
                }
            }

            override fun delay(requestID: Int, ms: Int) {
                handler.postDelayed({ complete(requestID, true, "") }, maxOf(0, ms).toLong())
            }

        })
    }

}

/// AES-256-GCM under a Keystore key: `PREFIX ‖ base64(iv ‖ ciphertext)`.
private object SecretBox {
    const val PREFIX = "v1:"
    private const val ALIAS = "convo_secrets"

    private fun key(): javax.crypto.SecretKey {
        val store = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getEntry(ALIAS, null) as? java.security.KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = javax.crypto.KeyGenerator.getInstance(android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            android.security.keystore.KeyGenParameterSpec.Builder(ALIAS,
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build())
        return generator.generateKey()
    }

    fun seal(value: String): String {
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key())
        val sealed = cipher.iv + cipher.doFinal(value.toByteArray(Charsets.UTF_8))
        return PREFIX + Base64.encodeToString(sealed, Base64.NO_WRAP)
    }

    /// A value sealed by `seal`, or a legacy clear value as it is.
    fun open(stored: String): String {
        if (!stored.startsWith(PREFIX)) return stored
        return try {
            val bytes = Base64.decode(stored.removePrefix(PREFIX), Base64.NO_WRAP)
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key(), javax.crypto.spec.GCMParameterSpec(128, bytes, 0, 12))
            String(cipher.doFinal(bytes, 12, bytes.size - 12), Charsets.UTF_8)
        } catch (error: Exception) { "" }
    }
}

/// The pairing-code scanner: asks for the camera, lays a full-screen CameraX
/// preview over the app, decodes frames with ZXing as they arrive, and
/// closes on the first QR code (or on Cancel / Back) with the text or null.
private object QRScanner {
    private var overlay: android.view.View? = null
    private var callback: ((String?) -> Unit)? = null
    private val main = Handler(Looper.getMainLooper())

    fun scan(activity: androidx.activity.ComponentActivity, done: (String?) -> Unit) {
        main.post {
            if (callback != null) { done(null); return@post }
            callback = done
            val granted = { androidx.core.content.ContextCompat.checkSelfPermission(activity, android.Manifest.permission.CAMERA) ==
                android.content.pm.PackageManager.PERMISSION_GRANTED }
            if (granted()) { open(activity); return@post }
            androidx.core.app.ActivityCompat.requestPermissions(activity, arrayOf(android.Manifest.permission.CAMERA), 4242)
            // No result callback without the activity's cooperation: watch for
            // the grant, and take focus returning without one as a refusal.
            var ticks = 0
            val poll = object : Runnable {
                override fun run() {
                    ticks += 1
                    when {
                        granted() -> open(activity)
                        ticks > 4 && activity.hasWindowFocus() -> finish(null)
                        ticks > 600 -> finish(null)
                        else -> main.postDelayed(this, 250)
                    }
                }
            }
            main.postDelayed(poll, 250)
        }
    }

    private fun open(activity: androidx.activity.ComponentActivity) {
        val frame = android.widget.FrameLayout(activity).apply {
            setBackgroundColor(android.graphics.Color.BLACK)
            isClickable = true
        }
        val preview = androidx.camera.view.PreviewView(activity)
        frame.addView(preview, android.widget.FrameLayout.LayoutParams(-1, -1))
        val density = activity.resources.displayMetrics.density
        val hint = android.widget.TextView(activity).apply {
            text = "Point the camera at a pairing code"
            setTextColor(android.graphics.Color.WHITE)
            textSize = 17f
            setShadowLayer(6f, 0f, 0f, android.graphics.Color.BLACK)
        }
        frame.addView(hint, android.widget.FrameLayout.LayoutParams(-2, -2,
            android.view.Gravity.BOTTOM or android.view.Gravity.CENTER_HORIZONTAL).apply { bottomMargin = (96 * density).toInt() })
        val cancel = android.widget.Button(activity).apply {
            text = "Cancel"
            setOnClickListener { finish(null) }
        }
        frame.addView(cancel, android.widget.FrameLayout.LayoutParams(-2, -2,
            android.view.Gravity.TOP or android.view.Gravity.START).apply {
                topMargin = (40 * density).toInt(); leftMargin = (16 * density).toInt() })
        activity.addContentView(frame, android.view.ViewGroup.LayoutParams(-1, -1))
        overlay = frame
        frame.isFocusableInTouchMode = true
        frame.requestFocus()
        frame.setOnKeyListener { _, keyCode, event ->
            if (keyCode == android.view.KeyEvent.KEYCODE_BACK && event.action == android.view.KeyEvent.ACTION_UP) { finish(null); true } else false
        }

        val future = androidx.camera.lifecycle.ProcessCameraProvider.getInstance(activity)
        future.addListener({
            val provider = try { future.get() } catch (error: Exception) { finish(null); return@addListener }
            val previewCase = androidx.camera.core.Preview.Builder().build().also { it.setSurfaceProvider(preview.surfaceProvider) }
            val analysis = androidx.camera.core.ImageAnalysis.Builder()
                .setBackpressureStrategy(androidx.camera.core.ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                .build()
            val reader = com.google.zxing.qrcode.QRCodeReader()
            val hints = mapOf(com.google.zxing.DecodeHintType.TRY_HARDER to true)
            analysis.setAnalyzer(java.util.concurrent.Executors.newSingleThreadExecutor()) { image ->
                try {
                    val plane = image.planes[0]
                    val buffer = plane.buffer
                    val data = ByteArray(buffer.remaining()).also { buffer.get(it) }
                    val source = com.google.zxing.PlanarYUVLuminanceSource(data, plane.rowStride, image.height,
                        0, 0, image.width, image.height, false)
                    val result = reader.decode(com.google.zxing.BinaryBitmap(com.google.zxing.common.HybridBinarizer(source)), hints)
                    main.post { finish(result.text) }
                } catch (none: Exception) {
                    // Nothing readable in this frame.
                } finally {
                    reader.reset()
                    image.close()
                }
            }
            try {
                provider.unbindAll()
                provider.bindToLifecycle(activity, androidx.camera.core.CameraSelector.DEFAULT_BACK_CAMERA, previewCase, analysis)
            } catch (error: Exception) {
                android.util.Log.w("Convo", "camera bind failed", error)
                finish(null)
            }
        }, androidx.core.content.ContextCompat.getMainExecutor(activity))
    }

    private fun finish(code: String?) {
        val done = callback ?: return
        callback = null
        overlay?.let { view ->
            (view.context as? androidx.activity.ComponentActivity)?.let { activity ->
                try { androidx.camera.lifecycle.ProcessCameraProvider.getInstance(activity).get().unbindAll() } catch (error: Exception) {}
            }
            (view.parent as? android.view.ViewGroup)?.removeView(view)
        }
        overlay = null
        done(code)
    }
}
