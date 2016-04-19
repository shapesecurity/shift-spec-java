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

exports.default = function (obj) { // todo destructuring parameter, pending node 6
  let nodes = obj.nodes;
  let enums = obj.enums;
  let namedTypes = obj.namedTypes;

  function inherits(child, parent) {
    let parents = nodes.get(child).parents;
    if (parents.indexOf(parent) === -1) {
      parents.push(parent);
    }
    nodes.get(parent).children.push(child);
  }

  namedTypes.forEach((type, name) => {
    if (type.kind === 'union') {
      if (nodes.has(name)) {
        throw `Node named ${name} already exists!`;
      }
      nodes.set(name, {children: [], parents: [], attributes: []});
      type.argument.forEach(t => {inherits(t.argument, name);});
      namedTypes.set(name, {kind: 'node', argument: name});
    }
  });

  let seen = new Map;
  function addUnions(type) {
    if (seen.has(type)) return seen.get(type);
    let ret;
    switch (type.kind) {
      case 'nullable':
      case 'list':
        type.argument = addUnions(type.argument);
        ret = type;
        break;
      case 'namedType':
        let child = namedTypes.get(type.argument);
        if (child.kind === 'union') {
          throw 'Not reached';
        }
        ret = addUnions(child);
        break;
      case 'union':
        let name = type.argument.map(t => t.argument).join('');
        nodes.set(name, {children: [], parents: [], attributes: []});
        type.argument.forEach(t => {
          if (t.kind === 'node' || t.kind === 'namedType') {
            inherits(t.argument, name);
          } else {
            throw `Union of unhandled type ${JSON.stringify(t)}`;
          }
        });
        ret = {kind: 'node', argument: name};
        break;
      default:
        ret = type;
    }
    seen.set(type, ret);
    return ret;
  }

  nodes.forEach(n => {
    n.attributes.forEach((a, i) => {n.attributes[i].type = addUnions(a.type);});
  });

  return {nodes, enums};
}