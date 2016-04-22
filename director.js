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

const outdir = 'reducer/';

let fs = require('fs');

let specConsumer = require('../shift-spec-consumer').default;
let spec = specConsumer(fs.readFileSync(require.resolve('../shift-spec/spec.idl'), 'utf8'), fs.readFileSync(require.resolve('../shift-spec/attribute-order.conf'), 'utf8'));
spec = require('./unions-to-interfaces').default(spec);
let nodes = spec.nodes;



const forbiddenNames = ['super']
function sanitize(str) {
  return forbiddenNames.indexOf(str) === -1 ? str : `_${str}`; // todo this is a bit dumb - what other names are reserved in Java?
}

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


let methods = new Map;


function methodNameFor(type) {
  switch (type.kind) {
    case 'nullable':
      if (type.argument.kind === 'list') {
        return `reduceMaybeList${type.argument.argument.argument}`;
      }
      return `reduceMaybe${type.argument.argument}`;
    case 'list':
      if (type.argument.kind === 'nullable') {
        return `reduceListMaybe${type.argument.argument.argument}`;
      }
      return `reduceList${type.argument.argument}`;
    case 'node':
      return `reduce${type.argument}`;
    default:
      console.log('---' + JSON.stringify(type))
      throw 'Not reached';
  }
}

function toJavaType(type) {
  switch (type.kind) {
    case 'nullable':
      return `Maybe<${toJavaType(type.argument)}>`;
    case 'list':
      return `ImmutableList<${toJavaType(type.argument)}>`;
    case 'node':
      return type.argument;
    default:
      throw 'Not reached';
  }
}

function nodeReducer(type, nodeName) {
  let node = nodes.get(type);
  let attrs = node.attributes.filter(a => isStatefulType(a.type));
  attrs.forEach(a => {direct(a.type);});
  let params = nodeName + attrs.map(a => `, ${methodNameFor(a.type)}(reducer, ${nodeName}.${sanitize(a.name)})`).join('');
  return `reducer.reduce${type}(${params})`;
}

function directNode(name) {
  direct({kind: 'node', argument: name});
}

function direct(type) {
  let methodName = methodNameFor(type);
  if (methods.has(methodName)) return;
  methods.set(methodName, null);

  let method;
  switch (type.kind) {
    case 'nullable':
      direct(type.argument);
      method = `
    @NotNull
    public static <State> Maybe<${type.argument.kind === 'list' ? 'ImmutableList<State>' : 'State'}> ${methodName}(
      @NotNull Reducer<State> reducer,
      @NotNull ${toJavaType(type)} maybe) {
        return maybe.map(x -> ${methodNameFor(type.argument)}(reducer, x));
      }
`;
      break;
    case 'list':
      direct(type.argument);
      method = `
    @NotNull
    public static <State> ImmutableList<${type.argument.kind === 'nullable' ? 'Maybe<State>' : 'State'}> ${methodName}(
      @NotNull Reducer<State> reducer,
      @NotNull ${toJavaType(type)} list) {
        return list.map(x -> ${methodNameFor(type.argument)}(reducer, x));
      }
`;
      break;
    case 'node':
      let node = nodes.get(type.argument);
      //console.log(type.argument, node);
      method = `
    @NotNull
    public static <State> State ${methodName}(
      @NotNull Reducer<State> reducer,
      @NotNull ${type.argument} node) {
`;
      if (node.children.length > 0) {
        /*
        let childSet = new Set;
        function addChildren(n) {
          let node = nodes.get(n);
          if (node.children.length > 0) {
            node.children.forEach(addChildren);
          } else {
            childSet.add(n);
          }
        }
        node.children.forEach(addChildren);
        let children = Array.from(childSet).sort();
        
        method += '        ' + children.map(child => `if (node instanceof ${child}) {
            ${child} tNode = (${child}) node);
            return ${nodeReducer(child, 'tNode')};
        }`).join(' else ') + ` else {
            throw new RuntimeException("Not reached");
        }
`;*/
        node.children.forEach(directNode);
        method += '        ' + node.children.map(child => `if (node instanceof ${child}) {
            return reduce${child}(reducer, (${child}) node);
        }`).join(' else ') + ` else {
            throw new RuntimeException("Not reached");
        }
`;

      } else {
        method += `        return ${nodeReducer(type.argument, 'node')};
`;
      }
      method += '    }';
      break;
    default:
      throw 'Not reached';
  }

  methods.set(methodName, method);
}

directNode('Program');


let content = `// Generated by shift-spec-java/director.js

/*
 * Copyright 2016 Shape Security, Inc.
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


package com.shapesecurity.shift.visitor;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.ast.*;

import org.jetbrains.annotations.NotNull;

public final class Director {`;

content += Array.from(methods.keys()).sort().map(methodName => methods.get(methodName)).join('\n');

content += '\n}\n';

fs.writeFile(outdir + 'Director.java', content, 'utf8');
