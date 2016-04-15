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
let webIDL = require('webidl2');

let spec = webIDL.parse(fs.readFileSync(require.resolve('shift-spec-idl/spec.idl'), 'utf-8'));
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






let superTypes = [];
let interfaceTypes = new Set;

let types = new Map;
let _implements = new Map;
let _extends = new Map;
let inherits = new Map;

let namedTypes = new Map;

const enums = new Map([
  ['CompoundAssignmentOperator', 'com.shapesecurity.shift.ast.operators.CompoundAssignmentOperator'],
  ['BinaryOperator', 'com.shapesecurity.shift.ast.operators.BinaryOperator'],
  ['UnaryOperator', 'com.shapesecurity.shift.ast.operators.UnaryOperator'],
  ['UpdateOperator', 'com.shapesecurity.shift.ast.operators.UpdateOperator'],
  ['VariableDeclarationKind', 'com.shapesecurity.shift.ast.VariableDeclarationKind']
]);


const forbiddenNames = ['super']
function sanitize(str) {
  return forbiddenNames.indexOf(str) === -1 ? str : `_${str}`; // todo this is a bit dumb - what other names are reserved in Java?
}

function isSimpleIdlType(type) {
  return !type.sequence && !type.generic && !type.nullable && !type.array && !type.union && typeof type.idlType === 'string';
}

function addImplements(child, parent) {
  if (!_implements.has(child)) {
    _implements.set(child, []);
  }
  _implements.get(child).push(parent);
}

function addExtends(child, parent) {
  if (_extends.has(child)) {
    throw `${child} attempting to extend ${parent} but already extends ${_extends.get(child)}`;
  }
  _extends.set(child, parent);
}

function addInherits(child, parent) {
  if (!inherits.has(child)) {
    inherits.set(child, []);
  }
  inherits.get(child).push(parent);
}

function addUnionType(idlTypeList, name) {
  let types = idlTypeList.map(t => {
    if (!isSimpleIdlType(t)) throw `Union of complex type ${t}`;
    return t.idlType;
  });
  if (name === void 0) name = types.join(''); // todo replace with default parameter
  if (interfaceTypes.has(name)) return name;
  types.forEach(t => {addImplements(t, name);});
  interfaceTypes.add(name);
  return name;
}

function addNamedType(type, name) {
  if (namedTypes.has(type)) {
    throw `Attempting to rename ${type}`;
  }
  namedTypes.set(type, name);
}

addNamedType('string', 'String');


function nameSimpleType(t) {
  if (namedTypes.has(t)) {
    return namedTypes.get(t);
  }
  return t;
}

function nameIdlType(t) {
  if (isSimpleIdlType(t)) {
    return nameSimpleType(t.idlType);
  }

  if (t.nullable) {
    if (t.union) {
      if (t.sequence || t.generic || t.array || !Array.isArray(t.idlType)) {
        throw `Complex nullable-union type ${JSON.stringify(t, null, '  ')}`;
      }
      return `Maybe<${addUnionType(t.idlType)}>`;
    }
    if (t.sequence || t.generic || t.array || t.union || typeof t.idlType !== 'string') {
      throw `Complex nullable type ${JSON.stringify(t, null, '  ')}`;
    }
    return `Maybe<${nameSimpleType(t.idlType)}>`;
  }

  if (t.array === 1) {
    if (t.union) {
      if (t.sequence || t.generic || t.nullable || !Array.isArray(t.idlType)) {
        throw `Complex array-of-union type ${JSON.stringify(t, null, '  ')}`;
      }
      if (t.nullableArray[0]) {
        return `ImmutableList<Maybe<${addUnionType(t.idlType)}>>`;
      }
      return `ImmutableList<${addUnionType(t.idlType)}>`;
    }
    if (t.sequence || t.generic || t.nullable || t.union || typeof t.idlType !== 'string') {
      throw `Complex array type ${JSON.stringify(t, null, '  ')}`;
    }
    if (t.nullableArray[0]) {
      return `ImmutableList<Maybe<${nameSimpleType(t.idlType)}>>`;
    }
    return `ImmutableList<${nameSimpleType(t.idlType)}>`;
  }

  if (t.union) {
    if (t.sequence || t.generic || t.nullable || t.array || !Array.isArray(t.idlType)) {
      throw `Complex union type ${JSON.stringify(t, null, '  ')}`;
    }
    return addUnionType(t.idlType);
  }

  throw `Unsupported IDL type ${JSON.stringify(t, null, '  ')}`;
}

// make type map, superTypes, interfaceTypes
for (let type of spec) {
  if (type.type === 'interface') {
    types.set(type.name, type);
    if (type.inheritance !== null) {
      addInherits(type.name, type.inheritance);
      if (superTypes.indexOf(type.inheritance) === -1) { // todo could use a set
        superTypes.push(type.inheritance);
      }
    }
  } else if (type.type === 'implements') {
    addInherits(type.target, type.implements);
    if (superTypes.indexOf(type.implements) === -1) { // todo could use a set
      superTypes.push(type.implements);
    }
  } else if (type.type === 'typedef') {
    if (type.name === 'string') continue;
    if (type.idlType.idlType === 'string') {
      addNamedType(type.name, 'String');
    } else if (type.idlType.union) {
      if (!type.idlType.sequence && !type.idlType.generic && !type.idlType.nullable && !type.idlType.array) {
        addUnionType(type.idlType.idlType, type.name);
      } else {
        addUnionType(type.idlType.idlType);
        addNamedType(type.name, nameIdlType(type.idlType));
      }
    } else {
      throw `Unsupported typedef ${type}`;
    }
  } else if (type.type === 'enum') {
    if (!enums.has(type.name)) {
      throw `Unsupported enum ${type}`;
    }
  } else {
    throw `Unsupported type ${type}`;
  }
}

let superInterfaces = superTypes.filter(t => {let f = types.get(t); return f.members.length === 0 || f.members.length === 1 && f.members[0].name === 'type';});
superInterfaces.forEach(t => interfaceTypes.add(t));





// set attributes and inheritance

let attributes = new Map;

function setAttrs(name) {
  if (attributes.has(name)) return;
  let type = types.get(name);
  let attrs = [];
  let parents = inherits.get(type.name);
  if (parents) {
    parents.forEach(p => {
      if (!attributes.has(p)) {
        setAttrs(p);
      }
      attrs.push(...attributes.get(p).map(a => ({
        name: a.name, type: a.type, inherited: true
      })));
    });
  }
  attrs.push(...type.members.filter(t => t.name !== 'type').map(t => ({
    name: t.name,
    type: nameIdlType(t.idlType),
    inherited: false
  })));
  let attrOrder = attrOrders.get(name);
  attrs.sort((a, b) => attrOrder.indexOf(a.name) - attrOrder.indexOf(b.name));
  attributes.set(name, attrs);
}

for (let name of types.keys()) {
  setAttrs(name);

  let type = types.get(name);
  let parents = inherits.get(type.name);
  if (parents) {
    parents.forEach(p => {
      if (superInterfaces.indexOf(p) !== -1) {
        addImplements(type.name, p);
      } else {
        addExtends(type.name, p);
      }
    });
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
`

// actually generate the files
for (let t of types.keys()) {
  if (interfaceTypes.has(t)) continue;

  let imp = _implements.get(t);
  let imps = imp ? ` implements ${imp.join(', ')}` : ''; // todo consider removing redundant `Node`s
  let ex = _extends.get(t);
  let exs = ex ? ` extends ${ex}` : '';

  let attrs = attributes.get(t);
  attrs.forEach(a => {a.name = sanitize(a.name);});

  let fields = attrs.filter(a => !a.inherited).map(a => `    @NotNull
    public final ${a.type} ${a.name};
`).join('\n');

  let ctorBodyLines = ex ? [`        super(${attrs.filter(a => a.inherited).map(a => a.name).join(', ')});`] : [];
  ctorBodyLines.push(...attrs.filter(a => !a.inherited).map(a => `        this.${a.name} = ${a.name};`));

  let ctorBody = ctorBodyLines.length > 0 ? `\n${ctorBodyLines.join('\n')}\n    ` : '';

  let ctor = `
    public ${t} (${attrs.map(a => `${a.type === 'boolean' ? '' : '@NotNull '}${a.type} ${a.name}`).join(', ')}) {${ctorBody}}
`;

  let imports = `
import org.jetbrains.annotations.NotNull;
import com.shapesecurity.functional.data.HashCodeBuilder;
` + 
    (attrs.some(a => a.type.match('ImmutableList')) ? 'import com.shapesecurity.functional.data.ImmutableList;\n' : '') +
    (attrs.some(a => a.type.match('Maybe')) ? 'import com.shapesecurity.functional.data.Maybe;\n' : '') +
    (attrs.filter(a => !a.inherited && enums.has(a.type)).map(a => `import ${enums.get(a.type)};\n`));


  let propEquals = a => a.type === 'boolean' || a.type === 'double' ? ` && this.${a.name} == ((${t}) object).${a.name}` : ` && this.${a.name}.equals(((${t}) object).${a.name})`;
  let equals = `
    @Override
    public boolean equals(Object object) {
        return object instanceof ${t}${attrs.map(propEquals).join('')};
    }
`;
  
  let hashCode = `
    @Override
    public int hashCode() {
        int code = HashCodeBuilder.put(0, "${t}");${attrs.map(a => `\n        code = HashCodeBuilder.put(code, this.${a.name});`).join('')}
        return code;
    }
`;

  let clazz = `${header}${imports}
public class ${t}${exs}${imps} {
${fields}
${ctor}
${equals}
${hashCode}
}
`;
  fs.writeFile(outdir + t + '.java', clazz, 'utf8', ()=>{});
}

for (let t of interfaceTypes) {
  let imp = _implements.get(t);
  if (t !== 'Node' && !imp) {
    imp = ['Node'];
  }

  let imps = imp ? ` extends ${imp.join(', ')}` : ''; // todo consider removing redundant `Node`s
  let body = `${header}
public interface ${t}${imps} {}
`
  fs.writeFile(outdir + t + '.java', body, 'utf8', ()=>{});
}



