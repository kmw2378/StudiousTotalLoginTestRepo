package nerds.studiousTestProject.studycafe.entity.hashtag;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@Builder
@Entity
@Getter
@NoArgsConstructor
public class HashtagRecord {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private Integer count;

    @Enumerated(EnumType.STRING)
    private HashtagName name;

    /*
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "cafe_id", nullable = false, foreignKey = @ForeignKey(ConstraintMode.NO_CONSTRAINT))
    private Studycafe studycafe;
    */
}
