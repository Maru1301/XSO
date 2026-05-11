import { mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { nextTick } from 'vue'
import App from './App.vue'

function mountLogin() {
  return mount(App, {
    props: {
      challengeId: 'challenge-1',
    },
  })
}

function okResponse(body: unknown): Response {
  return {
    ok: true,
    json: vi.fn().mockResolvedValue(body),
  } as unknown as Response
}

function failedResponse(): Response {
  return {
    ok: false,
    json: vi.fn(),
  } as unknown as Response
}

async function flushPromises() {
  await Promise.resolve()
  await nextTick()
}

describe('App', () => {
  const originalLocation = window.location

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn())
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: {
        ...originalLocation,
        assign: vi.fn(),
      },
    })
    vi.spyOn(window.localStorage.__proto__, 'setItem')
    vi.spyOn(window.sessionStorage.__proto__, 'setItem')
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: originalLocation,
    })
  })

  it('renders the initial login form', () => {
    const wrapper = mountLogin()

    expect(wrapper.get('h1').text()).toBe('Sign in')
    expect(wrapper.get('input[name="identifier"]').attributes('autocomplete')).toBe('username')
    expect(wrapper.get('input[name="password"]').attributes('autocomplete')).toBe('current-password')
    expect(wrapper.get('button[type="submit"]').text()).toBe('Continue')
    expect(wrapper.find('[role="alert"]').exists()).toBe(false)
  })

  it('shows a required field error without calling the backend', async () => {
    const wrapper = mountLogin()

    await wrapper.get('form').trigger('submit')

    expect(fetch).not.toHaveBeenCalled()
    expect(wrapper.get('[role="alert"]').text()).toBe('Enter your account and password.')
  })

  it('submits credentials with the active challenge and disables the submit button while pending', async () => {
    let resolveFetch: (response: Response) => void = () => {}
    vi.mocked(fetch).mockReturnValue(new Promise<Response>((resolve) => {
      resolveFetch = resolve
    }))
    const wrapper = mountLogin()

    await wrapper.get('input[name="identifier"]').setValue(' ada@example.com ')
    await wrapper.get('input[name="password"]').setValue('correct-password')
    await wrapper.get('form').trigger('submit')
    await nextTick()

    const button = wrapper.get('button[type="submit"]')
    expect(button.attributes('disabled')).toBeDefined()
    expect(button.text()).toBe('Signing in...')
    expect(fetch).toHaveBeenCalledWith('/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      credentials: 'include',
      body: JSON.stringify({
        challengeId: 'challenge-1',
        identifier: 'ada@example.com',
        password: 'correct-password',
      }),
    })

    resolveFetch(okResponse({ redirectUrl: 'https://sample.example.com/auth/callback?code=code-1' }))
    await flushPromises()

    expect(button.attributes('disabled')).toBeUndefined()
  })

  it('clears the password and shows a generic error after invalid credentials', async () => {
    vi.mocked(fetch).mockResolvedValue(failedResponse())
    const wrapper = mountLogin()

    await wrapper.get('input[name="identifier"]').setValue('ada@example.com')
    await wrapper.get('input[name="password"]').setValue('wrong-password')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect((wrapper.get('input[name="identifier"]').element as HTMLInputElement).value).toBe('ada@example.com')
    expect((wrapper.get('input[name="password"]').element as HTMLInputElement).value).toBe('')
    expect(wrapper.get('[role="alert"]').text()).toBe('Invalid account or password.')
  })

  it('shows a generic service error when the backend request fails', async () => {
    vi.mocked(fetch).mockRejectedValue(new Error('network unavailable'))
    const wrapper = mountLogin()

    await wrapper.get('input[name="identifier"]').setValue('ada@example.com')
    await wrapper.get('input[name="password"]').setValue('correct-password')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(wrapper.get('[role="alert"]').text()).toBe('Unable to sign in right now.')
  })

  it('redirects to the backend-provided URL without writing tokens to browser storage', async () => {
    vi.mocked(fetch).mockResolvedValue(okResponse({
      redirectUrl: 'https://sample.example.com/auth/callback?code=code-1',
      accessToken: 'must-not-be-used',
    }))
    const localStorageSetItem = vi.mocked(window.localStorage.setItem)
    const sessionStorageSetItem = vi.mocked(window.sessionStorage.setItem)
    const wrapper = mountLogin()

    await wrapper.get('input[name="identifier"]').setValue('ada@example.com')
    await wrapper.get('input[name="password"]').setValue('correct-password')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(window.location.assign).toHaveBeenCalledWith('https://sample.example.com/auth/callback?code=code-1')
    expect(localStorageSetItem).not.toHaveBeenCalled()
    expect(sessionStorageSetItem).not.toHaveBeenCalled()
  })

  it('does not redirect when the backend omits a redirect URL', async () => {
    vi.mocked(fetch).mockResolvedValue(okResponse({}))
    const wrapper = mountLogin()

    await wrapper.get('input[name="identifier"]').setValue('ada@example.com')
    await wrapper.get('input[name="password"]').setValue('correct-password')
    await wrapper.get('form').trigger('submit')
    await flushPromises()

    expect(window.location.assign).not.toHaveBeenCalled()
    expect(wrapper.get('[role="alert"]').text()).toBe('Unable to sign in right now.')
  })
})
