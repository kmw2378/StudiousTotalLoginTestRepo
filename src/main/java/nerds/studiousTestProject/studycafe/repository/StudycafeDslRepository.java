package nerds.studiousTestProject.studycafe.repository;

import com.querydsl.core.types.dsl.BooleanExpression;
import com.querydsl.jpa.impl.JPAQueryFactory;
import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.studycafe.dto.QSearchResponse;
import nerds.studiousTestProject.studycafe.dto.SearchRequest;
import nerds.studiousTestProject.studycafe.dto.SearchResponse;
import org.springframework.stereotype.Repository;

import java.sql.Time;
import java.util.Date;
import java.util.List;

import static io.jsonwebtoken.lang.Strings.hasText;
import static nerds.studiousTestProject.studycafe.entity.QStudycafe.studycafe;

@Repository
@RequiredArgsConstructor
public class StudycafeDslRepository {
    private final JPAQueryFactory queryFactory;

    public List<SearchResponse> searchAll(SearchRequest searchRequest) {
        return queryFactory
                .select(
                        new QSearchResponse(
                                studycafe.name,
                                studycafe.photo,    // 사진 (추후 수정 예정)
                                studycafe.accumReserveCount,
                                studycafe.duration,    // 역까지 걸리는 시간
                                studycafe.totalGrade
                        )
                )
                .from(studycafe)
                .where(
                        openTime(searchRequest.getStartTime(), searchRequest.getEndTime()),
                        dateAndTimeNotReserved(searchRequest.getDate(), searchRequest.getStartTime(), searchRequest.getEndTime()),
                        headCountBetween(searchRequest.getHeadCount()),
                        keywordContains(searchRequest.getKeyword())
                )
                .fetch();
    }

    private BooleanExpression openTime(Time startTime, Time endTime) {
        BooleanExpression startTimeLoe = startTimeLoe(startTime);
        BooleanExpression endTimeGoe = endTimeGoe(endTime);
        return startTimeLoe != null ? startTimeLoe.and(endTimeGoe) : endTimeGoe;
    }

    private BooleanExpression startTimeLoe(Time startTime) {
        return startTime != null ? studycafe.startTime.loe(startTime) : null;
    }

    private BooleanExpression endTimeGoe(Time endTime) {
        return endTime != null ? studycafe.endTime.goe(endTime) : null;
    }

    private BooleanExpression dateAndTimeNotReserved(Date date, Time startTime, Time endTime) {
        BooleanExpression dateEq = dateEq(date);
        BooleanExpression startTimeGoe = startTimeGoe(startTime);
        BooleanExpression endTimeLoe = endTimeLoe(endTime);

        // 날짜가 선택 안 된 경우는 가능 시간 조회 불가능
        return dateEq != null ? studycafe.rooms.any().reservationRecords.any().date.eq(date)
                .and(startTimeGoe != null ? studycafe.rooms.any().reservationRecords.any().startTime.goe(startTime) : null)
                .and(endTimeLoe != null ? studycafe.rooms.any().reservationRecords.any().endTime.loe(endTime) : null)
                .not() : null;
    }

    private BooleanExpression dateEq(Date date) {
        return date != null ? studycafe.rooms.any().reservationRecords.any().date.eq(date) : null;
    }

    private BooleanExpression startTimeGoe(Time startTime) {
        return startTime != null ? studycafe.rooms.any().reservationRecords.any().startTime.goe(startTime) : null;
    }

    private BooleanExpression endTimeLoe(Time endTime) {
        return endTime != null ? studycafe.rooms.any().reservationRecords.any().endTime.loe(endTime) : null;
    }

    private BooleanExpression headCountBetween(Integer headCount) {
        BooleanExpression minHeadCountGoe = minHeadCountGoe(headCount);
        return minHeadCountGoe == null ? null : minHeadCountGoe.and(maxHeadCountLoe(headCount));
    }

    private BooleanExpression minHeadCountGoe(Integer headCount) {
        return headCount != null ? studycafe.rooms.any().minHeadCount.goe(headCount) : null;
    }

    private BooleanExpression maxHeadCountLoe(Integer headCount) {
        return headCount != null ? studycafe.rooms.any().maxHeadCount.loe(headCount) : null;
    }

    private BooleanExpression keywordContains(String keyword) {
        return hasText(keyword) ? studycafe.name.contains(keyword).or(studycafe.address.contains(keyword)) : null;
    }
}
