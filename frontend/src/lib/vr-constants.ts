/** Shared VR scoring constants used across detail panel and full-page views. */

export const VR_TAG_DESCRIPTIONS: Record<string, string> = {
  mem_corrupt: 'Memory corruption bug class',
  heap_corrupt: 'Heap-specific corruption (overflow, UAF, double free, type confusion)',
  user_mode_parser: 'User-mode parsing component (heap-heavy attack surface)',
  kernel: 'Kernel-mode component',
  remote_preauth: 'Network-reachable without authentication',
  scope_change: 'Sandbox or VM escape (Scope:Changed)',
  novel: 'No public exploit or disclosure',
  patchable: 'KB patches available for binary diffing',
  high_impact: 'Remote Code Execution or Elevation of Privilege',
  info_leak: 'Information disclosure (ASLR/KASLR bypass potential)',
};
