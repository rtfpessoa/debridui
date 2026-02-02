import { NextRequest, NextResponse } from "next/server";

const MAX_REDIRECTS = 10;

function isPrivateUrl(url: string): boolean {
    try {
        const parsed = new URL(url);
        const hostname = parsed.hostname.toLowerCase();

        // Block localhost
        if (hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1") {
            return true;
        }

        // Block private IP ranges
        const ipParts = hostname.split(".").map(Number);
        if (ipParts.length === 4 && ipParts.every((p) => !isNaN(p))) {
            // 10.0.0.0/8
            if (ipParts[0] === 10) return true;
            // 172.16.0.0/12
            if (ipParts[0] === 172 && ipParts[1] >= 16 && ipParts[1] <= 31) return true;
            // 192.168.0.0/16
            if (ipParts[0] === 192 && ipParts[1] === 168) return true;
            // 169.254.0.0/16 (link-local)
            if (ipParts[0] === 169 && ipParts[1] === 254) return true;
        }

        // Block cloud metadata endpoints
        if (hostname === "metadata.google.internal" || hostname === "169.254.169.254") {
            return true;
        }

        // Only allow http/https
        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
            return true;
        }

        return false;
    } catch {
        return true;
    }
}

async function resolveRedirects(url: string): Promise<string> {
    let currentUrl = url;
    for (let i = 0; i < MAX_REDIRECTS; i++) {
        const response = await fetch(currentUrl, {
            method: "HEAD",
            redirect: "manual",
        });
        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get("location");
            if (!location) break;
            // Handle relative redirects
            currentUrl = new URL(location, currentUrl).href;
        } else {
            break;
        }
    }
    return currentUrl;
}

export async function GET(request: NextRequest) {
    const url = request.nextUrl.searchParams.get("url");
    if (!url) {
        return NextResponse.json({ error: "Missing url parameter" }, { status: 400 });
    }

    // SSRF protection: block private IPs and restricted protocols
    if (isPrivateUrl(url)) {
        return NextResponse.json({ error: "URL not allowed" }, { status: 403 });
    }

    // Restrict to safe methods only
    const method = request.nextUrl.searchParams.get("method") || "GET";
    if (method !== "GET" && method !== "HEAD") {
        return NextResponse.json({ error: "Method not allowed" }, { status: 405 });
    }

    try {
        // Resolve redirects without downloading content
        const resolve = request.nextUrl.searchParams.get("resolve") === "true";
        if (resolve) {
            const resolvedUrl = await resolveRedirects(url);
            return NextResponse.json({ resolvedUrl });
        }

        const response = await fetch(url, {
            method,
            redirect: "follow",
        });

        // For HEAD requests, return headers as JSON
        if (method === "HEAD") {
            return NextResponse.json({
                contentType: response.headers.get("content-type"),
                contentLength: response.headers.get("content-length"),
                status: response.status,
            });
        }

        // For GET requests (downloading torrent files), stream the response
        return new NextResponse(response.body, {
            status: response.status,
            headers: {
                "content-type": response.headers.get("content-type") || "application/octet-stream",
            },
        });
    } catch (error) {
        return NextResponse.json(
            { error: error instanceof Error ? error.message : "Fetch failed" },
            { status: 500 }
        );
    }
}
