package com.zephyrus.auth.dto;


import java.io.Serializable;

public class RoleDto implements Serializable {
    private Long id;
    private String roleName;
    private ClientDto client;
    private String moduleName;
}
