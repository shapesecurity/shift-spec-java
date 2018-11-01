'use strict';

const fs = require('fs');
const path = require('path');

const toInterfaces = require('./unions-to-interfaces.js');
const specConsumer = require('shift-spec-consumer');
const spec = toInterfaces(specConsumer(fs.readFileSync(require.resolve('shift-spec-idl/spec.idl'), 'utf8'), fs.readFileSync(require.resolve('shift-spec-idl/attribute-order.conf'), 'utf8')));
const nodes = spec.nodes;
const enums = spec.enums;

function isStatefulType(type) {
  switch (type.kind) {
    case 'value':
    case 'enum':
      return false;
    case 'nullable':
      return isStatefulType(type.argument);
    case 'list':
    case 'node':
      return true;
    case 'union':
    case 'namedType':
    default:
      throw 'Not reached';
  }
}

function sanitize(name) {
  return name === 'super' ? '_super' : name;
}

function toJavaType(type, nodeType) {
  switch (type.kind) {
    case 'nullable':
      return `Maybe<${toJavaType(type.argument, nodeType)}>`;
    case 'list':
      return `ImmutableList<${toJavaType(type.argument, nodeType)}>`;
    case 'node':
      return typeof nodeType === 'undefined' ? type.argument : nodeType;
    case 'value':
      switch (type.argument) {
        case 'string':
          return 'String';
        case 'boolean':
          return 'boolean';
        case 'double':
          return 'double';
        default:
          throw new Error(`Unhandled value type ${type.argument}`);
      }
    default:
      throw new Error('Not reached');
  }
}


function makeHeader(filename) {
  return `// Generated by ${path.basename(filename)}
/**
 * Copyright 2018 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
`;
}

function ensureDir(dir) {
  try {
    fs.mkdirSync(dir);
  } catch (ignored) {}
}

module.exports = {
  spec,
  nodes,
  enums,
  makeHeader,
  isStatefulType,
  sanitize,
  toJavaType,
  ensureDir,
};
