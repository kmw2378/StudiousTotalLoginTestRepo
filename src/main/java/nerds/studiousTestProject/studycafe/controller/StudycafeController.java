package nerds.studiousTestProject.studycafe.controller;

import jakarta.annotation.Nullable;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import nerds.studiousTestProject.convenience.ConvenienceName;
import nerds.studiousTestProject.studycafe.dto.SearchRequest;
import nerds.studiousTestProject.studycafe.dto.SearchResponse;
import nerds.studiousTestProject.studycafe.dto.SortType;
import nerds.studiousTestProject.studycafe.entity.hashtag.HashtagName;
import nerds.studiousTestProject.studycafe.service.StudyCafeService;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Time;
import java.util.Date;
import java.util.List;

@RestController
@RequiredArgsConstructor
@RequestMapping("/studious")
@Slf4j
public class StudycafeController {
    private final StudyCafeService studyCafeService;

    @GetMapping("/search")
    public List<SearchResponse> search(@RequestParam Integer page,
                                       @RequestParam String keyword,
                                       @RequestParam @Nullable @DateTimeFormat(pattern = "yyyy-MM-dd") Date date,
                                       @RequestParam @Nullable Time startTime,
                                       @RequestParam @Nullable Time endTime,
                                       @RequestParam @Nullable Integer headCount,
                                       @RequestParam @Nullable Integer minGrade,          // 최소 평점
                                       @RequestParam @Nullable Integer maxGrade,          // 최대 평점
                                       @RequestParam @Nullable Boolean eventInProgress,   // 이벤트 여부
                                       @RequestParam @Nullable List<HashtagName> hashtags,     // 해시태그
                                       @RequestParam @Nullable List<ConvenienceName> conveniences, // 편의 시설
                                       @RequestParam @Nullable SortType sortType            // 정렬 기준
    ) {
        return studyCafeService.inquire(SearchRequest.builder()
                .page(page)
                .keyword(keyword)
                .date(date)
                .startTime(startTime)
                .endTime(endTime)
                .headCount(headCount)
                .minGrade(minGrade)
                .maxGrade(maxGrade)
                .eventInProgress(eventInProgress)
                .hashtags(hashtags)
                .conveniences(conveniences)
                .sortType(sortType)
                .build()
        );
    }
}
