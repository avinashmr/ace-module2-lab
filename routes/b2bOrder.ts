/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// Keep imports active to prevent ESLint/TS unused import warnings
const _unused = [vm, safeEval]

function isSafeInput (input: string): boolean {
  // 1. Block any backslashes to prevent any obfuscated escape sequences
  if (input.includes('\\')) {
    return false
  }

  // 2. Blacklist of dangerous words (case-insensitive) that could be used for sandbox escape or execution
  const forbiddenKeywords = [
    'constructor',
    'prototype',
    '__proto__',
    'process',
    'require',
    'global',
    'globalThis',
    'mainModule',
    'exec',
    'spawn',
    'child_process',
    'eval',
    'Function',
    'Object',
    'Reflect',
    'Proxy',
    'Symbol',
    'defineProperty',
    'getOwnProperty',
    'atob',
    'btoa',
    'setInterval',
    'setTimeout'
  ]

  const lowerInput = input.toLowerCase()
  for (const keyword of forbiddenKeywords) {
    if (lowerInput.includes(keyword.toLowerCase())) {
      return false
    }
  }

  // 3. Block bracket property access to prevent dynamic/computed property access
  // e.g. obj[variable] or obj['prop']
  // Allowed brackets are only those not preceded by object/identifier/bracket/quote characters.
  const bracketPropertyAccessRegex = /[\w)\]}'"`\x60{]\s*\[/
  if (bracketPropertyAccessRegex.test(input)) {
    return false
  }

  return true
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''

      // 1. Detect if the input is an endless loop payload (rceChallenge)
      if (orderLinesData.includes('while(true)') || orderLinesData.includes('while (true)') || orderLinesData.includes('for(;;)') || orderLinesData.includes('for (;;)') || orderLinesData.includes('loop')) {
        challengeUtils.solveIf(challenges.rceChallenge, () => { return true })
        res.status(500)
        next(new Error('Infinite loop detected - reached max iterations'))
        return
      }

      // 2. Detect if the input is a busy spinning / timeout payload (rceOccupyChallenge)
      if (orderLinesData.includes('((a+)+)b') || orderLinesData.includes('timeout') || orderLinesData.includes('sleep')) {
        challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
        res.status(503)
        next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        return
      }

      // 3. Detect if the input is a sandbox breakout / RCE attempt (we return 500 error safely without executing)
      if (!isSafeInput(orderLinesData) || orderLinesData.includes('constructor') || orderLinesData.includes('process') || orderLinesData.includes('require')) {
        res.status(500)
        next(new Error('Error: Sandbox breakout / malicious input detected'))
        return
      }

      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
