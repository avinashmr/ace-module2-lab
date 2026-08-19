/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

function parseMath (str: string): number {
  let pos = 0
  const cleanStr = str.replace(/\s+/g, '')

  function peek (): string {
    return cleanStr[pos] || ''
  }

  function consume (char?: string): string {
    const next = peek()
    if (char && next !== char) {
      throw new Error(`Expected ${char} but got ${next}`)
    }
    if (next) pos++
    return next
  }

  function parseExpression (): number {
    return parseAdditive()
  }

  function parseAdditive (): number {
    let left = parseMultiplicative()
    while (true) {
      const op = peek()
      if (op === '+' || op === '-') {
        consume()
        const right = parseMultiplicative()
        if (op === '+') left += right
        else left -= right
      } else {
        break
      }
    }
    return left
  }

  function parseMultiplicative (): number {
    let left = parsePrimary()
    while (true) {
      const op = peek()
      if (op === '*' || op === '/' || op === '%') {
        consume()
        const right = parsePrimary()
        if (op === '*') left *= right
        else if (op === '/') left /= right
        else left %= right
      } else {
        break
      }
    }
    return left
  }

  function parsePrimary (): number {
    const next = peek()
    if (next === '(') {
      consume('(')
      const val = parseExpression()
      consume(')')
      return val
    }
    if (next === '-') {
      consume('-')
      return -parsePrimary()
    }
    if (next === '+') {
      consume('+')
      return parsePrimary()
    }
    let numStr = ''
    while (/[0-9.]/.test(peek())) {
      numStr += consume()
    }
    if (numStr === '') {
      throw new Error('Expected number')
    }
    return parseFloat(numStr)
  }

  const result = parseExpression()
  if (pos < cleanStr.length) {
    throw new Error('Unexpected extra characters')
  }
  return result
}

function safelyEvaluate (code: string): string {
  const trimmed = code.trim()

  // Case 1: Double-quoted string literal
  if (/^"([^"\\]|\\.)*"$/.test(trimmed)) {
    try {
      return JSON.parse(trimmed)
    } catch {
      return trimmed.slice(1, -1).replace(/\\(.)/g, '$1')
    }
  }

  // Case 2: Single-quoted string literal
  if (/^'([^'\\]|\\.)*'$/.test(trimmed)) {
    return trimmed.slice(1, -1).replace(/\\(.)/g, '$1')
  }

  // Case 3: Backtick-quoted string literal
  if (/^`([^`\\]|\\.)*`$/.test(trimmed) && !trimmed.includes('${')) {
    return trimmed.slice(1, -1).replace(/\\(.)/g, '$1')
  }

  // Case 4: Safe math/numeric expression (no letters, only digits, math operators, space)
  if (/^[0-9+\-*/%().\s]+$/.test(trimmed)) {
    return String(parseMath(trimmed))
  }

  throw new Error('Unsafe or unsupported expression')
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    let username = user.username

    if (username?.match(/#{(.*)}/) !== null && utils.isChallengeEnabled(challenges.usernameXssChallenge)) {
      req.app.locals.abused_ssti_bug = true
      const code = username?.substring(2, username.length - 1)
      try {
        if (!code) {
          throw new Error('Username is null')
        }
        username = safelyEvaluate(code)
      } catch (err) {
        username = '\\\\\\\\' + username
      }
    } else {
      username = '\\\\\\\\' + username
    }

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (username) {
      template = template.replace(/_username_/g, '!{username}')
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      const CSP = `img-src 'self' ${user?.profileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      const context = new Proxy(user, {
        get: (target, prop) => {
          if (prop === 'username') {
            return username
          }
          const val = Reflect.get(target, prop)
          if (typeof val === 'function') {
            return val.bind(target)
          }
          return val
        }
      }) as any

      res.send(fn(context))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
