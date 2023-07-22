package nerds.studiousTestProject.studycafe.dto;

import lombok.Builder;
import lombok.Data;
import nerds.studiousTestProject.convenience.ConvenienceName;
import nerds.studiousTestProject.studycafe.entity.hashtag.HashtagName;

import java.sql.Time;
import java.util.Date;
import java.util.List;

@Builder
@Data
public class SearchRequest {
    private Integer page;
    private String keyword;
    private Date date;
    private Time startTime;
    private Time endTime;
    private Integer headCount;
    private Integer minGrade;
    private Integer maxGrade;
    private Boolean eventInProgress;
    private List<HashtagName> hashtags;
    private List<ConvenienceName> conveniences;
    private SortType sortType;
}
