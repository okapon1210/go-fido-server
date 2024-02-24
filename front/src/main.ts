import './style.css'

import { uint8ArrayToBase64, base64ToUint8Array } from "../util"

const BASE_URL = "http://localhost:8080"

const getRegisterOptions = async (name: string, displayName: string) => {
  const url = new URL("/register/start", BASE_URL)
  const body = JSON.stringify({
    name,
    displayName
  })
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body,
  })
  if (!res.ok) {
    throw new Error("failed to fetch options")
  }
  const mayBeOptions = await res.json()
  const options: PublicKeyCredentialCreationOptions = {
    challenge: base64ToUint8Array(mayBeOptions.challenge),
    timeout: mayBeOptions.timeout,
    attestation: mayBeOptions.attestation,
    excludeCredentials: mayBeOptions.excludeCredentials,
    authenticatorSelection: mayBeOptions.authenticatorSelection,
    pubKeyCredParams: mayBeOptions.pubKeyCredParams,
    rp: mayBeOptions.rp,
    user: {
      id: base64ToUint8Array(mayBeOptions.user.id),
      name: mayBeOptions.user.name,
      displayName: mayBeOptions.user.displayName,
    },
    extensions: mayBeOptions.extensions,
  }
  return options
}

const postRegisterResult = async (
  id: string,
  type: string,
  response: AuthenticatorAttestationResponse,
) => {
  const url = new URL("/register/end", BASE_URL)
  const body = JSON.stringify({
    id,
    type,
    response: {
      clientDataJSON: uint8ArrayToBase64(
        new Uint8Array(response.clientDataJSON)
      ),
      attestationObject: uint8ArrayToBase64(
        new Uint8Array(response.attestationObject)
      ),
      transports: response.getTransports(),
    },
  })
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body,
  })

  if (!res.ok) {
    throw new Error(`${res.status}: ${res.statusText}`)
  }
}

const register = async () => {
  console.log('register button clicked')
  const userIdInput = document.querySelector<HTMLInputElement>('#name')
  if (!userIdInput) {
    throw new Error("can't read userId")
  }
  try {
    const options = await getRegisterOptions(userIdInput.value, "okapon")

    const mayBeCredential = await navigator.credentials.create({ publicKey: options })

    if (!mayBeCredential || mayBeCredential.type !== 'public-key') {
      throw new Error('credential is null')
    }

    const credential = mayBeCredential as PublicKeyCredential

    const response = credential.response as AuthenticatorAttestationResponse

    postRegisterResult(credential.id, credential.type, response)

    // const JSONtext = new TextDecoder('utf-8').decode(response.clientDataJSON)

    // const C = JSON.parse(JSONtext)

    // console.log("sending challenge: ", C.challenge) // なぜか / が _ に変換される

  } catch (e) {
    console.error(e)
  }
  return
}

const getRequestOptions = async (
  name: string
) => {
  const url = new URL('/attestation/start', BASE_URL)
  const body = JSON.stringify({
    name,
    userVerification: "required"
  })
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body,
  })
  if (!res.ok) {
    throw new Error('failed to fetch options')
  }

  const mayBeOptions = await res.json()
  const allowCredentials: PublicKeyCredentialDescriptor[] =
    mayBeOptions.allowCredentials.map(
      (cred: PublicKeyCredentialDescriptor) => ({
        id: base64ToUint8Array(cred.id),
        transports: cred.transports,
        type: cred.type,
      })
    )
  const options: PublicKeyCredentialRequestOptions = {
    challenge: base64ToUint8Array(mayBeOptions.challenge),
    timeout: mayBeOptions.timeout,
    rpId: mayBeOptions.rpId,
    allowCredentials: allowCredentials,
    userVerification: mayBeOptions.userVerification,
    extensions: mayBeOptions.extensions,
  }
  return options
}

const postSigninResult = async (
  id: string,
  response: AuthenticatorAssertionResponse
) => {
  const url = new URL('/attestation/end', BASE_URL)
  const body = JSON.stringify({
    id,
    response: {
      clientDataJSON: uint8ArrayToBase64(
        new Uint8Array(response.clientDataJSON)
      ),
      authenticatorData: uint8ArrayToBase64(
        new Uint8Array(response.authenticatorData)
      ),
      signature: uint8ArrayToBase64(new Uint8Array(response.signature)),
      userHandle: response.userHandle
        ? uint8ArrayToBase64(new Uint8Array(response.userHandle))
        : null,
    },
  })

  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body,
  })
  if (!res.ok) {
    throw new Error('failed to fetch options')
  }
}

const signin = async () => {
  console.log('signin button clicked')
  const userIdInput = document.querySelector<HTMLInputElement>("#name")
  if (!userIdInput) {
    throw new Error("can't read userId")
  }
  try {
    const options = await getRequestOptions(userIdInput.value)

    // Call navigator.credentials.get() and pass options as the publicKey option. Let credential be the result of the successfully resolved promise. If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable from the context available in the rejected promise. For information on different error contexts and the circumstances leading to them, see § 6.3.3 The authenticatorGetAssertion Operation.
    const mayBeCredential = await navigator.credentials.get({
      publicKey: options,
    })
    if (!mayBeCredential || mayBeCredential.type !== 'public-key') {
      throw new Error('credential is null')
    }

    const credential = mayBeCredential as PublicKeyCredential

    const response = credential.response as AuthenticatorAssertionResponse

    postSigninResult(credential.id, response)

    console.log(response)
  } catch (e) {
    console.error(e)
  }
  return
}

const init = () => {
  const registerButton = document.querySelector<HTMLButtonElement>('#register')
  if (!registerButton) {
    console.error('registerButton is not found')
    return
  }

  registerButton.addEventListener('click', register)

  const signinButton = document.querySelector<HTMLButtonElement>('#signin')
  if (!signinButton) {
    console.error('signinButton is not found')
    return
  }

  signinButton.addEventListener('click', signin)

}

window.onload = () => {
  init()
}
