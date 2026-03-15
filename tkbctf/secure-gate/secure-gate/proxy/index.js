const http = require("node:http");
const express = require("express");
const Busboy = require("busboy");

const app = express();

const BACKEND_HOST = process.env.BACKEND_HOST || "backend";
const BACKEND_PORT = Number(process.env.BACKEND_PORT) || 8080;

const SQLI_PATTERNS = [
  /'[^']*(\b(or|and|union|select|insert|update|delete|drop|alter|exec)\b|--|;)/i,
  /(union\s*(--[^\n]*\n\s*)*(all\s+)?(select|values))/i,
  /(\bselect\b[\s\S]*?\bfrom[\s"'[\x60(])/i,
  /(insert\s+into)/i,
  /(update\s+[\s\S]*?\sset\s)/i,
  /(delete\s+from)/i,
  /(drop\s+(table|database))/i,
  /(\bsleep\s*\(|\bbenchmark\s*\(|\bwaitfor\b)/i,
  /(load_file|into\s+(out|dump)file)/i,
  /\/\*[\s\S]*?\*\//,
];

function isSQLi(value) {
  return typeof value === "string" && SQLI_PATTERNS.some((p) => p.test(value));
}

const ALLOWED_CHARSETS = /^(utf-8|us-ascii|iso-8859-1|ascii)$/i;

function parseMultipart(headers, body) {
  return new Promise((resolve, reject) => {
    const values = [];
    const bb = Busboy({
      headers,
      limits: { fieldSize: 1024 * 1024, fileSize: 1024 * 1024 },
    });

    bb.on("field", (_name, value, info) => {
      if (value === undefined || info.valueTruncated) {
        reject(new Error("Invalid field"));
      } else {
        values.push(value);
      }
    });

    bb.on("file", (_name, stream, info) => {
      stream.resume();
      if (info.filename) values.push(info.filename);
    });

    bb.on("finish", () => resolve(values));
    bb.on("error", reject);
    bb.end(body);
  });
}

function forward(req, body, res) {
  const headers = {
    ...req.headers,
    host: `${BACKEND_HOST}:${BACKEND_PORT}`,
    "content-length": body.length,
  };
  delete headers["transfer-encoding"];

  const proxy = http.request(
    {
      hostname: BACKEND_HOST,
      port: BACKEND_PORT,
      path: req.url,
      method: req.method,
      headers,
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      proxyRes.pipe(res);
    }
  );

  proxy.on("error", () => {
    if (!res.headersSent) {
      res.status(502).json({ error: "Backend error" });
    }
  });

  proxy.end(body);
}

app.use((req, res) => {
  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));

  req.on("end", async () => {
    const body = Buffer.concat(chunks);
    const contentType = (req.headers["content-type"] || "").toLowerCase();
    const values = [];

    try {
      const url = new URL(req.url, "http://localhost");
      for (const value of url.searchParams.values()) {
        values.push(value);
      }
    } catch {
      return res.status(400).json({ error: "Bad request" });
    }

    try {
      if (contentType.includes("multipart/form-data")) {
        const bodyStr = body.toString();
        const charsetMatch = bodyStr.match(/charset\s*=\s*([^\s;\r\n"']+)/gi);
        if (charsetMatch) {
          for (const m of charsetMatch) {
            const cs = m.replace(/charset\s*=\s*/i, "");
            if (!ALLOWED_CHARSETS.test(cs)) throw new Error("Unsupported charset");
          }
        }
        values.push(...(await parseMultipart(req.headers, body)));
      } else if (contentType.includes("urlencoded")) {
        for (const value of new URLSearchParams(body.toString()).values()) {
          values.push(value);
        }
      } else if (contentType.includes("json")) {
        JSON.parse(body.toString(), (_key, value) => {
          if (typeof value !== "object") values.push(String(value));
          return value;
        });
      } else if (body.length > 0) {
        values.push(body.toString());
      }
    } catch {
      return res.status(400).json({ error: "Bad request" });
    }

    if (values.some(isSQLi)) {
      return res.status(403).json({ error: "Forbidden" });
    }

    forward(req, body, res);
  });
});

app.listen(3000, () => {
  console.log("Proxy listening on :3000");
});
