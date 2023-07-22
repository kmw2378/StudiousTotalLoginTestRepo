package nerds.studiousTestProject.reservation.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import nerds.studiousTestProject.room.entity.Room;
import nerds.studiousTestProject.user.entity.member.Member;

import java.sql.Time;
import java.util.Date;

@AllArgsConstructor
@Builder
@Entity
@Getter
@NoArgsConstructor
public class ReservationRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "member_id", foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    private Member member;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "room_id", foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    private Room room;

    private String name;
    private String phoneNumber;
    private Date date;
    private Time startTime;
    private Time endTime;
    private Integer duration;
    private Integer headCount;

    @Enumerated(value = EnumType.STRING)
    private ReservationStatus status;

    private String request;
}
