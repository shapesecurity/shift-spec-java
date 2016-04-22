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

const outdir = 'ast/';

let fs = require('fs');

let specConsumer = require('../shift-spec-consumer').default;
let spec = specConsumer(fs.readFileSync(require.resolve('../shift-spec/spec.idl'), 'utf8'), fs.readFileSync(require.resolve('../shift-spec/attribute-order.conf'), 'utf8'));
spec = require('./unions-to-interfaces').default(spec);
let nodes = spec.nodes;
let enums = spec.enums;

const enumImports = new Map([
  ['CompoundAssignmentOperator', 'com.shapesecurity.shift.ast.operators.CompoundAssignmentOperator'],
  ['BinaryOperator', 'com.shapesecurity.shift.ast.operators.BinaryOperator'],
  ['UnaryOperator', 'com.shapesecurity.shift.ast.operators.UnaryOperator'],
  ['UpdateOperator', 'com.shapesecurity.shift.ast.operators.UpdateOperator'],
  ['VariableDeclarationKind', 'com.shapesecurity.shift.ast.VariableDeclarationKind']
]);


const extraMethods = new Map([
  ['Expression', `
    @NotNull
    public Precedence getPrecedence();
`],
  ['ArrayExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['ArrowExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.ASSIGNMENT;
    }
`],
  ['AssignmentExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.ASSIGNMENT;
    }
`],
  ['BinaryExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return this.operator.getPrecedence();
    }
`],
  ['CallExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.CALL;
    }
`],
  ['ClassExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['CompoundAssignmentExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.ASSIGNMENT;
    }
`],
  ['ConditionalExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.CONDITIONAL;
    }
`],
  ['FunctionExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['IdentifierExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['LiteralBooleanExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['LiteralInfinityExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['LiteralNullExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['LiteralNumericExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['LiteralRegExpExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['LiteralStringExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['MemberExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        if (this.object instanceof Super) {
          return Precedence.MEMBER;
        }
        Precedence p = ((Expression) this.object).getPrecedence();
        if (p == Precedence.CALL) {
            return Precedence.CALL;
        }
        return Precedence.MEMBER;
    }
`],
  ['NewExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return this.arguments.isEmpty() ? Precedence.NEW : Precedence.MEMBER;
    }
`],
  ['NewTargetExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.MEMBER;
    }
`],
  ['ObjectExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['TemplateExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return this.tag.map(tag -> {
            Precedence tagPrecedence = tag.getPrecedence();
            if (tagPrecedence == Precedence.CALL) {
                return Precedence.CALL;
            }
            return Precedence.MEMBER;
        }).orJust(Precedence.MEMBER);
    }
`],
  ['ThisExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PRIMARY;
    }
`],
  ['UnaryExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.PREFIX;
    }
`],
  ['UpdateExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return this.isPrefix ? Precedence.PREFIX : Precedence.POSTFIX;
    }
`],
  ['YieldExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.ASSIGNMENT;
    }
`],
  ['YieldGeneratorExpression', `
    @Override
    @NotNull
    public Precedence getPrecedence() {
        return Precedence.ASSIGNMENT;
    }
`],
]);



const forbiddenNames = ['super']
function sanitize(str) {
  return forbiddenNames.indexOf(str) === -1 ? str : `_${str}`; // todo this is a bit dumb - what other names are reserved in Java?
}

function isJavaInterfaceType(name) {
  let type = nodes.get(name);
  return type.attributes.length === 0 && type.children.length !== 0;
}

function toJavaType(type) {
  switch (type.kind) {
    case 'nullable':
      return `Maybe<${toJavaType(type.argument)}>`;
    case 'list':
      return `ImmutableList<${toJavaType(type.argument)}>`;
    case 'value':
      switch (type.argument) {
        case 'string':
          return 'String';
        case 'boolean':
          return 'boolean';
        case 'double':
          return 'double';
        default:
          throw `Unhandled value type ${type.argument}`;
      }
    case 'node':
    case 'enum':
      return type.argument;
    case 'union':
    case 'namedType':
      throw 'Not reached'; // eliminated by unions-to-interfaces
  }
}


const header = `// Generated by shift-java-gen/ast.JSON

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

package com.shapesecurity.shift.ast;
`;

// actually generate the files
// first, Java classes (abstract and concrete)
for (let n of Array.from(nodes.keys()).filter(n => !isJavaInterfaceType(n))) {
  let node = nodes.get(n);

  let imp = node.parents.filter(isJavaInterfaceType);
  let imps = imp.length > 0 ? ` implements ${imp.join(', ')}` : ''; // todo consider removing redundant `Node`s
  let ex = node.parents.filter(n => !isJavaInterfaceType(n));
  if (ex.length > 1) {
    throw `${n} extends multiple types`;
  }
  let exs = ex.length === 1 ? ` extends ${ex}` : '';

  let attrs = node.attributes;
  attrs.forEach(a => {a.name = sanitize(a.name); a.type = toJavaType(a.type);});

  let fields = attrs.filter(a => !a.inherited).map(a => `    @NotNull
    public final ${a.type} ${a.name};
`).join('\n');

  let ctorBodyLines = ex.length === 1 ? [`        super(${attrs.filter(a => a.inherited).map(a => a.name).join(', ')});`] : [];
  ctorBodyLines.push(...attrs.filter(a => !a.inherited).map(a => `        this.${a.name} = ${a.name};`));

  let ctorBody = ctorBodyLines.length > 0 ? `\n${ctorBodyLines.join('\n')}\n    ` : '';

  let ctor = `
    public ${n} (${attrs.map(a => `${a.type === 'boolean' ? '' : '@NotNull '}${a.type} ${a.name}`).join(', ')}) {${ctorBody}}
`;

  let extra = extraMethods.has(n) ? extraMethods.get(n) : '';

  let imports = `
import org.jetbrains.annotations.NotNull;
import com.shapesecurity.functional.data.HashCodeBuilder;
` + 
    (attrs.some(a => a.type.match('ImmutableList')) ? 'import com.shapesecurity.functional.data.ImmutableList;\n' : '') +
    (attrs.some(a => a.type.match('Maybe')) ? 'import com.shapesecurity.functional.data.Maybe;\n' : '') +
    (attrs.filter(a => !a.inherited && enums.has(a.type)).map(a => `import ${enumImports.get(a.type)};\n`)) +
    (extra.match('Precedence') ? 'import com.shapesecurity.shift.ast.operators.Precedence;\n' : '');


  let propEquals = a => a.type === 'boolean' || a.type === 'double' ? ` && this.${a.name} == ((${n}) object).${a.name}` : ` && this.${a.name}.equals(((${n}) object).${a.name})`;
  let equals = `
    @Override
    public boolean equals(Object object) {
        return object instanceof ${n}${attrs.map(propEquals).join('')};
    }
`;
  
  let hashCode = `
    @Override
    public int hashCode() {
        int code = HashCodeBuilder.put(0, "${n}");${attrs.map(a => `\n        code = HashCodeBuilder.put(code, this.${a.name});`).join('')}
        return code;
    }
`;


  let clazz = `${header}${imports}
public ${node.children.length === 0 ? '' : 'abstract '}class ${n}${exs}${imps} {
${fields}
${ctor}
${equals}
${hashCode}${extra}
}
`;
  fs.writeFile(outdir + n + '.java', clazz, 'utf8');
}

// then, Java interfaces
for (let n of Array.from(nodes.keys()).filter(isJavaInterfaceType)) {
  let node = nodes.get(n);

  let extra = extraMethods.has(n) ? extraMethods.get(n) : '';

  let imports = extra.match('Precedence') ? `
import org.jetbrains.annotations.NotNull;
import com.shapesecurity.shift.ast.operators.Precedence;
` : '';

  let imp = node.parents.filter(isJavaInterfaceType);
  if (imp.length !== node.parents.length) {
    console.log(node.parents)
    console.log(imp)

    throw `Interface type ${n} extends some type`;
  }

  let imps = imp.length > 0 ? ` extends ${imp.join(', ')}` : ''; // todo consider removing redundant `Node`s


  let body = `${header}${imports}
public interface ${n}${imps} {${extra}}
`;

  fs.writeFile(outdir + n + '.java', body, 'utf8');
}


