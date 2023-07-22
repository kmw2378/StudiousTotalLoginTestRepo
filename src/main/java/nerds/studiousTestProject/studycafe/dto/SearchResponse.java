package nerds.studiousTestProject.studycafe.dto;

import com.querydsl.core.annotations.QueryProjection;
import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class SearchResponse {
    private String cafeName;
    private String photo;
    private Integer accumRevCnt;
    private Integer duration;
    private Double grade;

    @QueryProjection
    public SearchResponse(String cafeName, String photo, Integer accumRevCnt, Integer duration, Double grade) {
        this.cafeName = cafeName;
        this.photo = photo;
        this.accumRevCnt = accumRevCnt;
        this.duration = duration;
        this.grade = grade;
    }
}
