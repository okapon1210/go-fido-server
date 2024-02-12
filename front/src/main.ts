import './style.css'

const BASE_URL = "http://localhost:8080"

const convertUint8Array = (mayBeBin: unknown): Uint8Array => {
  return Uint8Array.from(
    atob(mayBeBin as string),
    c => (
      c.charCodeAt(0)
    )
  )
}

const getRegisterOptions = async () => {
  const url = new URL("/register/start", BASE_URL)
  const res = await fetch(url, {
    method: "POST"
  })
  if (!res.ok) {
    throw new Error("failed to fetch options")
  }
  const mayBeOptions = await res.json()
  const options: PublicKeyCredentialCreationOptions = {
    challenge: convertUint8Array(mayBeOptions.challenge),
    attestation: mayBeOptions.attestation,
    pubKeyCredParams: mayBeOptions.pubKeyCredParams,
    rp: mayBeOptions.rp,
    user: {
      id: convertUint8Array(mayBeOptions.user.id),
      name: mayBeOptions.user.name,
      displayName: mayBeOptions.user.displayName,
    },
  }
  return options
}

const postRegisterResult = async (
  response: AuthenticatorAttestationResponse,
  results: AuthenticationExtensionsClientOutputs
) => {
  const url = new URL("/register/end", BASE_URL)
  const body = JSON.stringify({
    response: {
      clientDataJSON: Array.from(new Uint8Array(response.clientDataJSON)),
      attestationObject: Array.from(new Uint8Array(response.attestationObject)),
    },
    results,
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
  try {
    const options = await getRegisterOptions()

    const mayBeCredential = await navigator.credentials.create({ publicKey: options })

    if (!mayBeCredential || mayBeCredential.type !== 'public-key') {
      throw new Error('credential is null')
    }

    const credential = mayBeCredential as PublicKeyCredential

    const response = credential.response as AuthenticatorAttestationResponse

    const clientExtensionResults = credential.getClientExtensionResults()

    postRegisterResult(response, clientExtensionResults)

    const JSONtext = new TextDecoder('utf-8').decode(response.clientDataJSON)

    const C = JSON.parse(JSONtext)

    console.log(C.challenge)

    // const attestationObject = response.attestationObject

  } catch (e) {
    console.error(e)
  }
  return
}

const signin = () => {
  console.log('signin button clicked')
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
