package com.harikesh.spring.security.student;

import com.google.common.collect.Lists;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

@RestController
@RequestMapping("/management/api/v1/students")
public class StudentManagementController {

    private static final List<Student> STUDENTS = Lists.newArrayList(
            new Student(1, "James"),
            new Student(2, "Maria Jones"),
            new Student(3, "John Smith")
    );

    // hasRole('ROLE_ADMIN') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')
    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public List<Student> getAllStudents() {
        System.out.println("StudentManagementController.getAllStudents");
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('student:write')")
    public ResponseEntity<Student> registerNewStudent(@RequestBody Student student) throws URISyntaxException {
        System.out.println("StudentManagementController.registerNewStudent");
        System.out.println("student = " + student);
        return ResponseEntity.created(new URI("/1")).body(student);
    }

    @DeleteMapping("{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public ResponseEntity<?> deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("StudentManagementController.deleteStudent");
        System.out.println("studentId = " + studentId);
        return ResponseEntity.noContent().build();
    }

    @PutMapping("{studentId}")
    @PreAuthorize("hasAuthority('student:write')")
    public ResponseEntity<Student> updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println("StudentManagementController.updateStudent");
        System.out.println("studentId = " + studentId + ", student = " + student);
        return ResponseEntity.ok(student);
    }
}
