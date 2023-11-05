package com.wongweiye.model;

import jakarta.persistence.*;
import lombok.*;

import java.util.Objects;

@Getter
@Setter
@RequiredArgsConstructor
@Entity
@Table(name = "Notes")
public class Note {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    String title;

    @Column(columnDefinition="text")
    String description;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User user;

    public Note(String title, String description) {
        this.title = title;
        this.description = description;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Note note = (Note) o;
        return Objects.equals(id, note.id) && Objects.equals(title, note.title) && Objects.equals(description, note.description) && Objects.equals(user, note.user);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, title, description, user);
    }

    @Override
    public String toString() {
        return "Note{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", description='" + description + '\'' +
                ", user=" + user +
                '}';
    }
}
