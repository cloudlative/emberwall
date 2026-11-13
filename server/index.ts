#!/usr/bin/env node
// Emberwall server: serves the web app and the API. Configuration comes from the environment.
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer } from './start';

const here = dirname(fileURLToPath(import.meta.url));
// dist/ sits next to the bundle (dist-server/) and one level above server/ in a source checkout.
startServer({ staticDir: process.env.EMBERWALL_STATIC ?? join(here, '..', 'dist') });
