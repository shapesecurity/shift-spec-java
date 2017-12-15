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

'use strict';

let fs = require('fs');

const outDir = 'out/';
try { fs.mkdirSync(outDir); } catch (ignored) {}

let specConsumer = require('shift-spec-consumer');
let spec = specConsumer(fs.readFileSync(require.resolve('shift-spec-idl/spec.idl'), 'utf8'), fs.readFileSync(require.resolve('shift-spec-idl/attribute-order.conf'), 'utf8'));
spec = require('./unions-to-interfaces').default(spec);
let nodes = spec.nodes;
let enums = spec.enums;

let keywords = ['super'];

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
  return (keywords.indexOf(name) !== -1 ? '_' : '') + name;
}

function cap(name) {
  return name[0].toUpperCase() + name.slice(1);
}

let branchContent = `// Generated by shift-spec-java/branch.js

/*
 * Copyright 2017 Shape Security, Inc.
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

package com.shapesecurity.shift.es2016.path;


import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es2016.ast.*;

import java.util.Objects;


public abstract class Branch {
	abstract public Maybe<? extends Node> step(Node node);

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		return o != null && getClass() == o.getClass();
	}

	@Override
	public int hashCode() {
		return Objects.hash(getClass());
	}
`;

function base(type) {
  if (type.kind === 'list') return base(type.argument);
  if (type.kind === 'nullable') return base(type.argument);
  return type.argument;
}

let classContent = [];
let classes = [];

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type));

  attrs.forEach(a => {
    let isList = a.type.kind === 'list';
    let isMaybe = a.type.kind === 'nullable';// || a.type.kind === 'list' && a.type.argument.kind === 'nullable';
    let isListMaybe = a.type.kind === 'list' && a.type.argument.kind === 'nullable';

    let name = `${typeName}${cap(a.name)}`;
    classContent.push(`
	public static ${name} ${name}_(${isList ? 'int index' : ''}) {
		return new ${name}(${isList ? 'index' : ''});
	}
`);

    let cl = `
class ${name} extends `;
    if (isListMaybe) {
      cl += `IndexedBranch {
	protected ${name}(int index) {
		super(index);
	}

	@Override
	public Maybe<? extends Node> step(Node node) {
		if (!(node instanceof ${typeName})) return Maybe.empty();
		return ((${typeName}) node).${sanitize(a.name)}.index(index).orJust(Maybe.empty());
	}
}`;
    } else if (isList) {
      cl += `IndexedBranch {
	protected ${name}(int index) {
		super(index);
	}

	@Override
	public Maybe<? extends Node> step(Node node) {
		if (!(node instanceof ${typeName})) return Maybe.empty();
		return ((${typeName}) node).${sanitize(a.name)}.index(index);
	}
}`;
    } else if (isMaybe) {
      cl += `Branch {
	@Override
	public Maybe<? extends Node> step(Node node) {
		if (!(node instanceof ${typeName})) return Maybe.empty();
		return ((${typeName}) node).${sanitize(a.name)};
	}
}`;
    } else {
      cl += `Branch {
	@Override
	public Maybe<? extends Node> step(Node node) {
		if (!(node instanceof ${typeName})) return Maybe.empty();
		return Maybe.of(((${typeName}) node).${sanitize(a.name)});
	}
}`;
    }

  classes.push(cl);
  });
}

branchContent += `${classContent.join('')}
}

abstract class IndexedBranch extends Branch {
	public final int index;

	protected IndexedBranch(int index) {
		this.index = index;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		IndexedBranch that = (IndexedBranch) o;
		return index == that.index;
	}

	@Override
	public int hashCode() {
		return Objects.hash(getClass(), index);
	}
}

${classes.join('\n')}
`;

fs.writeFileSync(outDir + 'Branch.java', branchContent, 'utf-8');
