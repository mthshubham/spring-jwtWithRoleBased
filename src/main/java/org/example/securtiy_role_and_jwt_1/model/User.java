// Data Transfer Object (D T O ) -- Basically it is use to hold the data for userDetails and userLogin data

package org.example.securtiy_role_and_jwt_1.model;

import jakarta.persistence.Column;

public class User {

// -----For Login details---

    private String username;
    private String password;

// ---- For User details
    private String firstName;
    private String lastName;
    private String gender;
    private String email;
    private String phoneNumber;
    private String country;
    private String city;
    private String state;
    private String zip;
    private String localAddress;

    // ----- Getter Setters

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getGender() {
        return gender;
    }

    public void setGender(String gender) {
        this.gender = gender;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhoneNumber() {
        return phoneNumber;
    }

    public void setPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
    }

    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getZip() {
        return zip;
    }

    public void setZip(String zip) {
        this.zip = zip;
    }

    public String getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(String localAddress) {
        this.localAddress = localAddress;
    }
}

/*
{
    "firstName":"Shubham",
    "lastName":"Kumar",
    "gender":"Male",
    "email":"thakurshubham440@gmail.com",
    "phoneNumber":"7260882890",
    "country":"India",
    "city":"Motihari",
    "state":"Bihar",
    "zip":"845401",
    "localAddress":"Chhatauni",
    "username":"mthshubham",
    "password":"845401"
}




 */