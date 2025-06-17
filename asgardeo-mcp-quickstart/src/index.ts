import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { McpAgent } from "agents/mcp";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { AsgardeoHandler, tokenExchangeCallback } from "./asgardeo-handler";
import { Props } from "./types";


export class MyMCP extends McpAgent<Env, {}, Props> {
  server = new McpServer({
    name: "Asgardeo OAuth Proxy Demo",
    version: "1.0.0",
  });

  async init() {
    this.server.tool(
      "whoami",
      "Get user info from your user profile",
      {},
      async () => ({
        content: [
          {
            type: "text",
            text: JSON.stringify({
              username: this.props.claimSet.username,
              given_name: this.props.claimSet.given_name,
              family_name: this.props.claimSet.family_name,
              organization: this.props.claimSet.org_name,
            }),
          },
        ],
      })
    );
  }
}

export default new OAuthProvider({
  apiRoute: "/sse",
  apiHandler: MyMCP.mount("/sse") as any,
  defaultHandler: AsgardeoHandler as any,
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  tokenExchangeCallback: tokenExchangeCallback
});

