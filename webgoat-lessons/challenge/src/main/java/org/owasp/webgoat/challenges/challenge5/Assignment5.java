/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.challenges.challenge5;

import lombok.extern.slf4j.Slf4j;
import org.owasp.webgoat.assignments.AssignmentEndpoint;
import org.owasp.webgoat.assignments.AttackResult;
import org.owasp.webgoat.challenges.Flag;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import javax.sql.DataSource;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

@RestController
@Slf4j
public class Assignment5 extends AssignmentEndpoint {

    private final DataSource dataSource;

    public Assignment5(DataSource dataSource) {
        this.dataSource = dataSource;
    }

    @PostMapping("/challenge/5")
    @ResponseBody
    public AttackResult login(HttpServletRequest request, HttpServletResponse response) throws SQLException{
        String usernamelogin = request.getParameter("username_login");
        String passwordlogin = request.getParameter("password_login");
        String query = "select password from challenge_users where userid = '?' and password = '?'";
        if (!StringUtils.hasText(usernamelogin) || !StringUtils.hasText(passwordlogin)) {
            return failed(this).feedback("required4").build();
        }
        if (!"Larry".equals(usernamelogin)) {
            return failed(this).feedback("user.not.larry").feedbackArgs(usernamelogin).build();
        }
        try (
            var connection = dataSource.getConnection();
            PreparedStatement statement =connection.prepareStatement(query) 
            ){

            statement.setString(1,usernamelogin);
            statement.setString(2,passwordlogin);

            ResultSet resultSet = statement.executeQuery();

            if (resultSet.next()) {
                return success(this).feedback("challenge.solved").feedbackArgs(Flag.FLAGS.get(5)).build();
            } else {
                return failed(this).feedback("challenge.close").build();
            }
        }
    }
}