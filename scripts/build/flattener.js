/**
 * Copyright 2018 Shape Security, Inc.
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

const { ensureDir, nodes, makeHeader, isStatefulType, sanitize, toJavaType, year } = require('../lib/utilities.js');

const outDir = 'out/';
const reducerDir = 'reducer/';
ensureDir(outDir + reducerDir);


let flatternerContent = `${makeHeader(__filename)}

package com.shapesecurity.shift.es${year}.reducer;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.es${year}.ast.*;
import javax.annotation.Nonnull;

public class Flattener extends MonoidalReducer<ImmutableList<Node>> {
    private static final Flattener INSTANCE = new Flattener();

    private Flattener() {
        super(new com.shapesecurity.functional.data.Monoid.ImmutableListAppend<>());
    }

    @Nonnull
    public static ImmutableList<Node> flatten(@Nonnull Program program) {
        return Director.reduceProgram(INSTANCE, program);
    }
`;

for (let typeName of Array.from(nodes.keys()).sort()) {
  let type = nodes.get(typeName);
  if (type.children.length !== 0) continue;

  let attrs = type.attributes.filter(f => isStatefulType(f.type));
  let attrStrings = attrs.map(f => `, @Nonnull ${toJavaType(f.type, 'ImmutableList<Node>')} ${sanitize(f.name)}`);
  flatternerContent += `
    @Nonnull
    @Override
    public ImmutableList<Node> reduce${typeName}(@Nonnull ${typeName} node${attrStrings.join('')}) {`;

  if (attrStrings.length === 0) {
    flatternerContent += `
        return ImmutableList.<Node>of(node);`;
  } else {
    flatternerContent += `
        return ImmutableList.<Node>of(node).append(super.reduce${typeName}(node${attrs.map(f => `, ${sanitize(f.name)}`).join('')}));`;
  }
  flatternerContent += `
    }
`;
}

flatternerContent += '}\n';

fs.writeFileSync(outDir + reducerDir + 'Flattener.java', flatternerContent, 'utf-8');
