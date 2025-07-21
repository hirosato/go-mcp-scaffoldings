import { Outlet, createRootRoute } from '@tanstack/react-router';
import { TanStackRouterDevtools } from '@tanstack/react-router-devtools';

import amplifyConfig from '@/amplify-config';
import { Authenticator } from '@aws-amplify/ui-react';
import '@aws-amplify/ui-react/styles.css';
import { Amplify } from 'aws-amplify';
import Header from '../components/Header';

Amplify.configure({ ...amplifyConfig });

export const Route = createRootRoute({
  component: () => (
    <>
      <Authenticator>
        <Authenticator.Provider>
          <Header />

          <Outlet />
          <TanStackRouterDevtools />
        </Authenticator.Provider>
      </Authenticator>
    </>
  ),
})
