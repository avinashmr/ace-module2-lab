/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string
    if (security.isRedirectAllowed(toUrl)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => { return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' || toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' || toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6' })
      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
      if (isRedirectSafe(toUrl)) {
        res.redirect(toUrl)
      } else {
        res.status(406)
        next(new Error('Unrecognized target URL for redirect: ' + toUrl))
      }
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isRedirectSafe (toUrl: string): boolean {
  if (!toUrl) return false
  try {
    const parsedTo = new URL(toUrl)
    for (const allowedUrl of security.redirectAllowlist) {
      try {
        const parsedAllowed = new URL(allowedUrl)
        if (parsedTo.protocol === parsedAllowed.protocol && parsedTo.host === parsedAllowed.host) {
          const toPath = parsedTo.pathname.replace(/\/+$/, '')
          const allowedPath = parsedAllowed.pathname.replace(/\/+$/, '')
          if (toPath === allowedPath || parsedTo.pathname.startsWith(parsedAllowed.pathname + '/')) {
            return true
          }
        }
      } catch {
        if (toUrl === allowedUrl) return true
      }
    }
  } catch {
    if (toUrl.startsWith('/') && !toUrl.startsWith('//') && !toUrl.startsWith('\\')) {
      return true
    }
  }
  return false
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
