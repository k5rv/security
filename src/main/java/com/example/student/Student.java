package com.example.student;

public class Student {

  private Integer studentId;
  private String studentName;

  public Student(String studentName) {
    this.studentName = studentName;
  }

  public Student(Integer studentId, String studentName) {
    this.studentId = studentId;
    this.studentName = studentName;
  }

  public Integer getStudentId() {
    return studentId;
  }

  public String getStudentName() {
    return studentName;
  }

  @Override
  public String toString() {
    return "Student{" +
            "studentId=" + studentId +
            ", studentName='" + studentName + '\'' +
            '}';
  }
}
