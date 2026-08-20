export interface SubscriptionObject {
  url: string;
  tag_prefix?: string;
  groups?: string[];
}

export type SubscriptionInput = string | SubscriptionObject;

export interface NormalizedSubscription {
  url: string;
  tag_prefix?: string;
  groups: string[];
}

export interface CustomNodeObject {
  node?: string;
  uri?: string;
  groups?: string[];
  [key: string]: any;
}

export type CustomNodeInput = string | CustomNodeObject | Record<string, any>;

export interface RelayConfig {
  url?: string;
  token?: string;
}

export interface Profile {
  name?: string;
  token?: string;
  secret_key?: string;
  subscriptions?: SubscriptionInput[];
  custom_nodes?: CustomNodeInput[];
  nodes?: CustomNodeInput[];
  template?: Record<string, any>;
  inbound_mode?: 'tun' | 'tproxy' | string;
  relay?: RelayConfig;
}

export interface AppConfig {
  relay?: RelayConfig;
  profiles: Profile[] | Record<string, Profile>;
  template?: Record<string, any>;
}

export interface Env {
  CONFIG?: string;
  [key: string]: any;
}
