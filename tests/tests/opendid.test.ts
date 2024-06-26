import { authentication } from './authentication'
import { TestState } from './test_state'
import { authorize } from './authorize'
import { challenge } from './challenge'
import { describe, it } from 'vitest'
import { token } from './token'

describe('OpenDID', async () => {
  it('should support Authorization Code Flow', async () => {
    const testState = new TestState()

    await authorize(testState)
    await challenge(testState)
    await authentication(testState)
    await token(testState)
  })

  it('should support the Implicit Flow', async () => {
    const testState = new TestState()

    await authorize(testState, true)
    await challenge(testState)
    await authentication(testState, true)
  })

  it('should not accept wrong challenge', async () => {
    const testState = new TestState()
    await authorize(testState)
    await challenge(testState, true)
  })
})
