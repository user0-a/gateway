package com.wwgateway.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration under the {@code wwgateway.*} prefix. */
@ConfigurationProperties(prefix = "wwgateway")
public class WwGatewayProperties {
    /** Base URL of the gateway (JWKS and policy snapshot are fetched from here). */
    private String gatewayUrl;
    /** Expected token issuer (GATEWAY_ISSUER of the gateway). */
    private String issuer;
    /** Name of THIS system as registered in the gateway (token "aud"). */
    private String audience;
    private boolean requireProofOfPossession = true;
    private long clockSkewSeconds = 5;
    private long proofMaxAgeSeconds = 60;
    private long snapshotMaxAgeSeconds = 30;
    private int maxBodyBytes = 1_048_576;
    /** memory (single instance / tests) or jdbc (clustered, needs a DataSource). */
    private String replayStore = "memory";

    public String getGatewayUrl() { return gatewayUrl; }
    public void setGatewayUrl(String v) { gatewayUrl = v; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String v) { issuer = v; }
    public String getAudience() { return audience; }
    public void setAudience(String v) { audience = v; }
    public boolean isRequireProofOfPossession() { return requireProofOfPossession; }
    public void setRequireProofOfPossession(boolean v) { requireProofOfPossession = v; }
    public long getClockSkewSeconds() { return clockSkewSeconds; }
    public void setClockSkewSeconds(long v) { clockSkewSeconds = v; }
    public long getProofMaxAgeSeconds() { return proofMaxAgeSeconds; }
    public void setProofMaxAgeSeconds(long v) { proofMaxAgeSeconds = v; }
    public long getSnapshotMaxAgeSeconds() { return snapshotMaxAgeSeconds; }
    public void setSnapshotMaxAgeSeconds(long v) { snapshotMaxAgeSeconds = v; }
    public int getMaxBodyBytes() { return maxBodyBytes; }
    public void setMaxBodyBytes(int v) { maxBodyBytes = v; }
    public String getReplayStore() { return replayStore; }
    public void setReplayStore(String v) { replayStore = v; }
}
