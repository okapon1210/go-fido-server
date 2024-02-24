export const uint8ArrayToBase64 = (bin: Uint8Array) =>
  btoa(String.fromCharCode(...bin))

export const base64ToUint8Array = (mayBeBin: unknown): Uint8Array =>
  Uint8Array.from(atob(mayBeBin as string), (c) => c.charCodeAt(0))
