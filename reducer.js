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

let Spec = require('./shift-spec-js/dist/index').default;

let keywords = ['super'];

function name(type, def) {
  if (!def) def = 'State';
  //console.log(type.typeName)
  switch (type.typeName) {
    case 'Maybe':
      return `Maybe<${name(type.argument, def)}>`;
    case 'List':
      return `ImmutableList<${name(type.argument, def)}>`;
    default:
      return def;
  }
}

function isStatefulType(type) {
  switch (type.typeName) {
    case 'Boolean':
    case 'Number':
    case 'String':
    case 'Enum':
      return false;
    case 'Maybe':
      return isStatefulType(type.argument);
    default:
      return true;
  } 
}

function sanitize(name) {
  return (keywords.indexOf(name) !== -1 ? '_' : '') + name;
}





let reducerContent = `/**
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

package com.shapesecurity.shift.visitor;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.ast.*;

import org.jetbrains.annotations.NotNull;

public interface Reducer<State> {`;

for (let typename of Object.keys(Spec).sort()) {
  let type = Spec[typename];
  let fields = type.fields.filter(f => f.name !== 'type' && isStatefulType(f.type)).map(f => `            @NotNull ${name(f.type)} ${sanitize(f.name)}`);
  if (fields.length === 0) {
    reducerContent += `
    @NotNull
    State reduce${type.typeName}(@NotNull ${type.typeName} node`
  } else {
  reducerContent += `
    @NotNull
    State reduce${type.typeName}(
            @NotNull ${type.typeName} node,
${fields.join(',\n')}`
  }
  reducerContent += ');\n';
}

reducerContent += '}';

require('fs').writeFileSync('Reducer.java', reducerContent, 'utf-8');








let monoidalContent = `/**
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

package com.shapesecurity.shift.visitor;

import com.shapesecurity.functional.data.*;
import com.shapesecurity.shift.ast.*;

import org.jetbrains.annotations.NotNull;

public class MonoidalReducer<State> implements Reducer<State> {
    @NotNull
    protected final Monoid<State> monoidClass;

    protected MonoidalReducer(@NotNull Monoid<State> monoidClass) {
        this.monoidClass = monoidClass;
    }

    protected State identity() {
        return this.monoidClass.identity();
    }

    protected State append(State a, State b) {
        return this.monoidClass.append(a, b);
    }

    protected State append(State a, State b, State c) {
        return append(append(a, b), c);
    }

    protected State append(State a, State b, State c, State d) {
        return append(append(a, b, c), d);
    }

    protected State fold(ImmutableList<State> as) {
        return as.foldLeft(this::append, this.identity());
    }

    protected State fold1(ImmutableList<State> as, State a) {
        return as.foldLeft(this::append, a);
    }

    @NotNull
    protected State o(@NotNull Maybe<State> s) {
        return s.orJust(this.identity());
    }
`;


function red(field) {
  switch(field.type.typeName) {
    case 'Maybe':
      return `o(${sanitize(field.name)})`;
    case 'List':
      if (field.type.argument.typeName === 'Maybe') {
        return `fold(Maybe.catMaybes(${sanitize(field.name)}))`
      }
      return `fold(${sanitize(field.name)})`;
    default:
      return sanitize(field.name);
  }
}

for (let typename of Object.keys(Spec).sort()) {
  let type = Spec[typename];
  let fields = type.fields.filter(f => f.name !== 'type' && isStatefulType(f.type));
  let fieldStrings = fields.map(f => `            @NotNull ${name(f.type)} ${sanitize(f.name)}`);
  if (fieldStrings.length === 0) {
    monoidalContent += `
    @NotNull
    @Override
    public State reduce${type.typeName}(@NotNull ${type.typeName} node`
  } else {
  monoidalContent += `
    @NotNull
    @Override
    public State reduce${type.typeName}(
            @NotNull ${type.typeName} node,
${fieldStrings.join(',\n')}`
  }
  let rv;
  if (fields.length === 0) {
    rv = 'this.identity()';
  } else if (fields.length === 1) {
    rv = red(fields[0]);
  } else if (fields.length === 2 && fields[1].type.typeName === 'List' && fields[0].type.typeName !== 'List') {
    rv = `fold1(${sanitize(fields[1].name)}, ${red(fields[0])})`;
  } else {
    rv = `append(${fields.map(red).join(', ')})`;
  }
  monoidalContent += `) {
        return ${rv};
    }
`;
}

monoidalContent += '}';

require('fs').writeFileSync('MonoidalReducer.java', monoidalContent, 'utf-8');











let cloneContent = `/**
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

package com.shapesecurity.shift.reducer;

import com.shapesecurity.functional.data.ImmutableList;
import com.shapesecurity.functional.data.Maybe;
import com.shapesecurity.shift.ast.*;
import com.shapesecurity.shift.visitor.Reducer;
import org.jetbrains.annotations.NotNull;

public class CloneReducer implements Reducer<Node> {`;

const ExpressionType = Spec.ExpressionStatement.fields[1].type;
const StatementType = Spec.LabeledStatement.fields[2].type;
const AssignmentTargetType = Spec.AssignmentExpression.fields[1].type;
const AssignmentTargetAssignmentTargetWithDefaultType = Spec.ArrayAssignmentTarget.fields[1].type.argument.argument;
const BindingBindingWithDefaultType = Spec.ArrayBinding.fields[1].type.argument.argument;
const PropertyNameType = Spec.BindingPropertyProperty.fields[1].type;
const SimpleAssignmentTargetType = Spec.UpdateExpression.fields[3].type;

function eq(t1, t2) {
  return t1 === t2;
}

function deUnion(type) {
  if (eq(type, ExpressionType)) return 'Expression';
  if (eq(type, ExpressionType)) return 'Statement';
  if (eq(type, AssignmentTargetType)) 'AssignmentTarget';
  if (eq(type, PropertyNameType)) return 'PropertyName';
  if (eq(type, SimpleAssignmentTargetType)) return 'SimpleAssignmentTarget';
  if (eq(type, AssignmentTargetAssignmentTargetWithDefaultType)) return 'AssignmentTargetAssignmentTargetWithDefault';
  if (eq(type, BindingBindingWithDefaultType)) return 'BindingBindingWithDefault';
  if (type.typeName === 'Union') {
    let rv = type.arguments.map(deUnion).join('');
    switch (rv) {
      case 'ObjectBindingArrayBindingBindingIdentifier':
        return 'Binding';
      case 'ObjectAssignmentTargetArrayAssignmentTargetBindingIdentifierComputedMemberAssignmentTargetStaticMemberAssignmentTarget':
        return 'AssignmentTarget';
      case 'ObjectAssignmentTargetArrayAssignmentTargetBindingIdentifierComputedMemberAssignmentTargetStaticMemberAssignmentTargetAssignmentTargetWithDefault':
        return 'AssignmentTargetAssignmentTargetWithDefault';
      case 'ObjectBindingArrayBindingBindingIdentifierBindingWithDefault':
        return 'BindingBindingWithDefault';
      case 'DoWhileStatementForInStatementForOfStatementForStatementWhileStatementClassDeclarationBlockStatementBreakStatementContinueStatementDebuggerStatementEmptyStatementExpressionStatementIfStatementLabeledStatementReturnStatementSwitchStatementSwitchStatementWithDefaultThrowStatementTryCatchStatementTryFinallyStatementVariableDeclarationStatementWithStatementFunctionDeclaration':
        return 'Statement';
      case 'BindingIdentifierComputedMemberAssignmentTargetStaticMemberAssignmentTarget':
        return 'SimpleAssignmentTarget';
      case 'VariableDeclarationObjectAssignmentTargetArrayAssignmentTargetBindingIdentifierComputedMemberAssignmentTargetStaticMemberAssignmentTarget':
        return 'VariableDeclarationAssignmentTarget';
      case 'ImportImportNamespace':
        return 'ImportDeclaration';
      case 'ExportAllFromExportFromExportLocalsExportExportDefault':
        return 'ExportDeclaration';
      case 'MethodDefinitionDataPropertyShorthandProperty':
        return 'ObjectProperty';
      case 'MethodGetterSetter':
        return 'MethodDefinition';
      case 'AssignmentTargetPropertyIdentifierAssignmentTargetPropertyProperty':
        return 'AssignmentTargetProperty';
      case 'BindingPropertyIdentifierBindingPropertyProperty':
        return 'BindingProperty';
      default:
        return rv;
    }
  } else {
    return type.typeName;
  }
}

function cl(field) {
  if (!isStatefulType(field.type)) {
    return `node.${sanitize(field.name)}`;
  }
  switch (field.type.typeName) {
    case 'List':
    case 'Maybe':
      return sanitize(field.name) + cl_(field.type);
    default:
      return `(${deUnion(field.type)}) ${sanitize(field.name)}`;
  }
}

function cl_(type) {
  if (type.typeName === 'List') {
    if (type.argument.typeName === 'Maybe') {
      return `.map(x -> x.map(y -> (${deUnion(type.argument.argument)}) y))`
    } else {
      return `.map(x -> (${deUnion(type.argument)}) x)`
    }
  } else if (type.typeName === 'Maybe') {
    return `.map(x -> (${deUnion(type.argument)}) x)`;
  } else {
    return '';
  }
}

for (let typename of Object.keys(Spec).sort()) {
  let type = Spec[typename];
  let fields = type.fields.filter(f => f.name !== 'type' && isStatefulType(f.type));
  let fieldStrings = fields.map(f => `            @NotNull ${name(f.type, 'Node')} ${sanitize(f.name)}`);
  if (fieldStrings.length === 0) {
    cloneContent += `
    @NotNull
    @Override
    public ${type.typeName} reduce${type.typeName}(@NotNull ${type.typeName} node`
  } else {
  cloneContent += `
    @NotNull
    @Override
    public ${type.typeName} reduce${type.typeName}(
            @NotNull ${type.typeName} node,
${fieldStrings.join(',\n')}`
  }
  cloneContent += `) {
        return new ${type.typeName}(${type.fields.filter(f => f.name !== 'type').map(cl).join(', ')});
    }
`;
}

cloneContent += '}';

require('fs').writeFileSync('CloneReducer.java', cloneContent, 'utf-8');







