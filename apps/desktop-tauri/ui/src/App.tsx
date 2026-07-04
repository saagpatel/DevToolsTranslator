import React from 'react';
import { BrowserRouter } from 'react-router-dom';
import type { DesktopClient } from './api/client.js';
import { createDesktopClient } from './api/client.js';
import { AppLayout } from './router.js';

export interface DesktopAppProps {
  readonly client?: DesktopClient;
}

export function DesktopApp({ client }: DesktopAppProps): React.JSX.Element {
  const resolvedClient = client ?? createDesktopClient();
  return (
    <BrowserRouter>
      <AppLayout client={resolvedClient} />
    </BrowserRouter>
  );
}

export default DesktopApp;
