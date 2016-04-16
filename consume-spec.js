/**
 * Copyright 2016 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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

"use strict";

let fs = require('fs');
let webIDL = require('webidl2');

let Spec = webIDL.parse(fs.readFileSync(require.resolve('shift-spec-idl/spec.idl'), 'utf-8'));
let attrOrders = parseAttrOrder(fs.readFileSync(require.resolve('shift-spec-idl/attribute-order.conf'), 'utf-8'));

function parseAttrOrder(f) {
  let attrOrder = new Map;
  let current = null;
  for (let line of f.split('\n')) {
    line = line.trim();
    if (line === '') continue;
    if (line[0] === '[') {
      let type = line.match(/^\[([^\]]*)\]$/)[1]
      current = [];
      attrOrder.set(type, current);
    } else {
      current.push(line);
    }
  }
  return attrOrder;
}

let nodes = new Map;
let enums = new Map;

/*
nodes: Map name => {
  attributes: [{
    name,
    idlType,
    inherited
  }],
  isLeaf: boolean,
  parents
} 

idlType:
{kind: simple | union     | maybe    | list
       name   | arguments | argument | argument
}

enums: Map name => [string]
*/


function inherits(type, parent) {
  nodes.get(type).parents.push(parent);
}

function addNamedType(name, type) {
  if (enums.has(name) || namedTypesIDL.has(name)) {
    throw `Attempting to redefine type ${name}`;
  }
  namedTypesIDL.set(name, type);
}

function addEnum(name, value) {
  if (enums.has(name) || namedTypesIDL.has(name)) {
    throw `Attempting to redefine enum ${name}`;
  }
  enums.set(name, value);
}


let idlTypes = new Map;
let idlTypeAliases = new Map;
let superTypes = new Set;
let namedTypesIDL = new Map;
let namedTypes = new Map;
let valueTypes = new Map([['DOMString', Value('string')], ['boolean', Value('boolean')], ['double', Value('double')]]);


for (let type of Spec) {
  if (type.type === 'interface') {
    idlTypes.set(type.name, type);
    nodes.set(type.name, {
      isLeaf: true,
      parents: []
    });
    if (type.inheritance !== null) {
      inherits(type.name, type.inheritance);
      superTypes.add(type.inheritance);
    }
  } else if (type.type === 'implements') {
    inherits(type.target, type.implements);
    superTypes.add(type.implements);
  } else if (type.type === 'typedef') {
    addNamedType(type.name, type.idlType);
  } else if (type.type === 'enum') {
    addEnum(type.name, type.values);
  } else {
    throw `Unsupported type ${type}`;
  }
}

superTypes.forEach(t => {nodes.get(t).isLeaf = false;});
namedTypesIDL.forEach((v, k) => namedTypes.set(k, idlTypeToType(v)));


function setAttrs(name) {
  let type = nodes.get(name);
  if (type.attributes) return;
  let attrs = type.attributes = [];

  type.parents.forEach(p => {
    setAttrs(p);
    attrs.push(...nodes.get(p).attributes.map(a => ({
      name: a.name,
      type: a.type,
      inherited: true
    })));
  });

  attrs.push(...idlTypes.get(name).members.filter(t => t.name !== 'type').map(t => ({
    name: t.name,
    type: idlTypeToType(t.idlType),
    inherited: false
  })));
  let attrOrder = attrOrders.get(name);
  attrs.sort((a, b) => attrOrder.indexOf(a.name) - attrOrder.indexOf(b.name));
}

function isSimpleIdlType(type) {
  return !type.sequence && !type.generic && !type.nullable && !type.array && !type.union && typeof type.idlType === 'string';
}

function Nullable(t) {
  return {kind: 'nullable', argument: t};
}

function Union(t) {
  return {kind: 'union', argument: t};
}

function List(t) {
  return {kind: 'list', argument: t};
}

function Value(t) {
  return {kind: 'value', argument: t};
}

function Node(t) {
  return {kind: 'node', argument: t};
}

function NamedType(t) {
  return {kind: 'namedType', argument: t};
}

function Enum(t) {
  return {kind: 'enum', argument: t};
}

function idlTypeToType(t) {
  if (typeof t === 'string') {
    if (nodes.has(t)) {
      return Node(t);
    }
    if (valueTypes.has(t)) {
      return valueTypes.get(t);
    }
    if (namedTypes.has(t)) {
      return NamedType(t);
    }
    if (enums.has(t)) {
      return Enum(t);
    }
    throw `Unidentified type ${t}`;
  }

  if (isSimpleIdlType(t)) {
    return idlTypeToType(t.idlType);
  }

  if (t.nullable) {
    if (t.union) {
      if (t.sequence || t.generic || t.array || !Array.isArray(t.idlType)) {
        throw `Complex nullable-union type ${JSON.stringify(t, null, '  ')}`;
      }
      return Nullable(Union(t.idlType.map(idlTypeToType)));
    }
    if (t.sequence || t.generic || t.array || t.union || typeof t.idlType !== 'string') {
      throw `Complex nullable type ${JSON.stringify(t, null, '  ')}`;
    }
    return Nullable(idlTypeToType(t.idlType));
  }

  if (t.array === 1) {
    if (t.union) {
      if (t.sequence || t.generic || t.nullable || !Array.isArray(t.idlType)) {
        throw `Complex array-of-union type ${JSON.stringify(t, null, '  ')}`;
      }
      if (t.nullableArray[0]) {
        return List(Nullable(Union(t.idlType.map(idlTypeToType)))); // `ImmutableList<Maybe<${addUnionType(t.idlType)}>>`;
      }
      return List(Union(t.idlType.map(idlTypeToType)));
    }
    if (t.sequence || t.generic || t.nullable || t.union || typeof t.idlType !== 'string') {
      throw `Complex array type ${JSON.stringify(t, null, '  ')}`;
    }
    if (t.nullableArray[0]) {
      return List(Nullable(idlTypeToType(t.idlType)));
    }
    return List(idlTypeToType(t.idlType));
  }

  if (t.union) {
    if (t.sequence || t.generic || t.nullable || t.array || !Array.isArray(t.idlType)) {
      throw `Complex union type ${JSON.stringify(t, null, '  ')}`;
    }
    return Union(t.idlType.map(idlTypeToType));
  }

  throw `Unsupported IDL type ${JSON.stringify(t, null, '  ')}`;
}


for (let name of nodes.keys()) {
  setAttrs(name);
}

// console.log(JSON.stringify(Array.from(nodes), null, '  '))
// console.log(JSON.stringify(Array.from(enums), null, '  '))
// console.log(JSON.stringify(Array.from(namedTypes), null, '  '))


module.exports.default = {nodes, enums, namedTypes};


