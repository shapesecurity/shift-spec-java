// Generated by ast.js
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


package com.shapesecurity.shift.es2016.ast;

import javax.annotation.Nonnull;
import com.shapesecurity.functional.data.HashCodeBuilder;

public class StaticMemberExpression extends MemberExpression {
    @Nonnull
    public final String property;


    public StaticMemberExpression (@Nonnull ExpressionSuper object, @Nonnull String property) {
        super(object);
        this.property = property;
    }


    @Override
    public boolean equals(Object object) {
        return object instanceof StaticMemberExpression && this.object.equals(((StaticMemberExpression) object).object) && this.property.equals(((StaticMemberExpression) object).property);
    }


    @Override
    public int hashCode() {
        int code = HashCodeBuilder.put(0, "StaticMemberExpression");
        code = HashCodeBuilder.put(code, this.object);
        code = HashCodeBuilder.put(code, this.property);
        return code;
    }

}
