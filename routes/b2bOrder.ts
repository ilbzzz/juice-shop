/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import vm from 'node:vm'
import { type Request, type Response, type NextFunction } from 'express'
// @ts-expect-error FIXME due to non-existing type definitions for notevil
import { eval as safeEval } from 'notevil'
// @ts-expect-error FIXME due to non-existing type definitions for esprima
import { parse as parseEsprima } from 'esprima'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

const FORBIDDEN_WORDS = [
  'constructor',
  'Function',
  'process',
  'require',
  'child_process',
  'mainModule',
  'getBuiltinModule',
  'execSync',
  'execFile',
  'exec',
  'spawn',
  'fork',
  'global',
  'globalThis',
  'window',
  'eval',
  '__proto__',
  'prototype',
  'import',
  'Reflect',
  'Proxy',
  'fromCharCode',
  'fromCodePoint',
  'class',
  'Buffer',
  'binding',
  'module',
  'exports',
  '__dirname',
  '__filename'
]

function isProhibited (str: string): boolean {
  if (!str) return false
  const lower = str.toLowerCase()
  for (const word of FORBIDDEN_WORDS) {
    if (word === 'Function') {
      if (str.includes('Function')) return true
    } else {
      if (lower.includes(word.toLowerCase())) return true
    }
  }
  return false
}

function checkAstNode (node: any): void {
  if (!node || typeof node !== 'object') return

  if (node.type === 'Identifier') {
    if (isProhibited(node.name)) {
      throw new Error('Prohibited identifier in orderLinesData: ' + node.name)
    }
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    if (isProhibited(node.value)) {
      throw new Error('Prohibited literal in orderLinesData: ' + node.value)
    }
  }

  if (node.type === 'MemberExpression') {
    if (node.property) {
      if (node.property.type === 'Identifier' && isProhibited(node.property.name)) {
        throw new Error('Prohibited property access in orderLinesData: ' + node.property.name)
      }
      if (node.property.type === 'Literal' && typeof node.property.value === 'string' && isProhibited(node.property.value)) {
        throw new Error('Prohibited property literal in orderLinesData: ' + node.property.value)
      }
    }
  }

  for (const key in node) {
    if (key === 'parent') continue
    const child = node[key]
    if (Array.isArray(child)) {
      for (const item of child) {
        checkAstNode(item)
      }
    } else if (child && typeof child === 'object' && child.type) {
      checkAstNode(child)
    }
  }
}

function validateOrderLinesData (code: string): void {
  if (!code) return
  if (isProhibited(code)) {
    throw new Error('Prohibited keywords detected in orderLinesData')
  }
  try {
    const ast = parseEsprima(code)
    checkAstNode(ast)
  } catch (err: any) {
    if (err.message?.includes('Prohibited')) {
      throw err
    }
  }
}

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''
      try {
        validateOrderLinesData(orderLinesData)
        const safeContext = {
          Function: function ForbiddenFunction () { throw new Error('Function evaluation forbidden') },
          eval: function ForbiddenEval () { throw new Error('eval is forbidden') },
          process: undefined,
          require: undefined,
          global: undefined,
          globalThis: undefined
        }
        const runSafeEval = (code: string) => safeEval(code, safeContext)
        const sandbox = { safeEval: runSafeEval, orderLinesData }
        vm.createContext(sandbox)
        vm.runInContext('safeEval(orderLinesData)', sandbox, { timeout: 2000 })
        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        if (utils.getErrorMessage(err).match(/Script execution timed out.*/) != null) {
          challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return true })
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          challengeUtils.solveIf(challenges.rceChallenge, () => { return utils.getErrorMessage(err) === 'Infinite loop detected - reached max iterations' })
          next(err)
        }
      }
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
