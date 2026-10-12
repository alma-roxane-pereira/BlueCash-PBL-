package com.bluecash.wallet.core

import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Talks to Person A's FastAPI backend. The JSON shapes are documented in API_CONTRACT.md;
 * if the backend differs, this is the only file that needs to change.
 */
class HttpMintApi(baseUrl: String) : MintApi {
    private val base = baseUrl.trimEnd('/')

    private fun call(method: String, path: String, body: JSONObject?): JSONObject {
        val conn = URL(base + path).openConnection() as HttpURLConnection
        try {
            conn.requestMethod = method
            conn.connectTimeout = 8000
            conn.readTimeout = 15000
            conn.setRequestProperty("Accept", "application/json")
            if (body != null) {
                conn.doOutput = true
                conn.setRequestProperty("Content-Type", "application/json")
                conn.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use { it.readText() } ?: ""
            if (code !in 200..299) throw MintApiException("server said $code: ${text.take(200)}")
            return JSONObject(text)
        } catch (e: MintApiException) {
            throw e
        } catch (e: Exception) {
            throw MintApiException("cannot reach server: ${e.message}", e)
        } finally {
            conn.disconnect()
        }
    }

    override fun getInfo(): MintInfo {
        val o = call("GET", "/mint/keys", null)
        return MintInfo(o.getJSONArray("keys").objects().map { MintKey.fromJson(it) }, o.getString("mint_pub"))
    }

    override fun registerDevice(req: RegisterRequest): DeviceCredential {
        val b = JSONObject().put("device_pub", req.devicePub).put("c0", req.c0).put("ts", req.ts).put("sig", req.sig)
        if (req.integrityToken != null) b.put("integrity_token", req.integrityToken)
        return DeviceCredential.fromJson(call("POST", "/mint/registerDevice", b).getJSONObject("credential"))
    }

    override fun issue(req: IssueRequest): IssueResponse {
        val o = call("POST", "/mint/issue", JSONObject().put("cred_id", req.credId).put("key_id", req.keyId)
            .put("blinded", req.blinded).put("c0", req.c0).put("ts", req.ts).put("sig", req.sig))
        return IssueResponse(o.getString("blind_sig"), o.getInt("leaf_index"), o.getInt("tree_size"),
            o.getJSONArray("proof").strings(), o.getString("root"))
    }

    override fun latestRoot(): AuditRoot {
        val o = call("GET", "/audit/root/latest", null)
        return AuditRoot(o.getString("root"), o.getInt("tree_size"), o.optLong("ts"))
    }

    override fun uploadBatch(receipts: List<Receipt>): SettlementResponse {
        val o = call("POST", "/settlement/uploadBatch", JSONObject().put("receipts", receipts.toJsonArray { it.toJson() }))
        val results = o.getJSONArray("results").objects().map {
            ReceiptResult(it.getString("receipt_id"), it.getString("status"), it.optString("detail"))
        }
        val revoked = o.optJSONArray("revoked")?.objects()?.map {
            Revocation(it.getString("cred_id"), it.optString("reason"), it.optLong("ts"))
        } ?: emptyList()
        return SettlementResponse(results, revoked)
    }

    override fun getRevocations(): List<Revocation> =
        call("GET", "/fraud/revocations", null).getJSONArray("revoked").objects().map {
            Revocation(it.getString("cred_id"), it.optString("reason"), it.optLong("ts"))
        }
}
