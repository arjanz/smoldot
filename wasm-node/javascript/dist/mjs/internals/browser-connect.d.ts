/// <reference lib="dom" />
import { Connection, ConnectionConfig } from './client.js';
/**
 * Tries to open a new connection using the given configuration.
 *
 * @see Connection
 * @throws any If the multiaddress couldn't be parsed or contains an invalid protocol.
 */
export declare function connect(config: ConnectionConfig): Connection;
/** Opens a raw WebTransport connection. Exported for the unit tests. */
export declare function connectWebTransport(config: ConnectionConfig): Connection;
