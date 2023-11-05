package com.wongweiye.repository;

import com.wongweiye.model.Note;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

@Repository
public interface NoteRepository extends JpaRepository<Note, Long> {

    @Query("select n from Note n where n.title = ?1 and n.user.id = ?2")
    Note getUserNote(String title, Long userId);

    @Modifying
    @Query("delete from Note n where n.title = ?1 and n.user.id = ?2")
    int deleteNote(String title, Long userId);

}
