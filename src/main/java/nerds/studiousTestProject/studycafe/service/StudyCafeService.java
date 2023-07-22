package nerds.studiousTestProject.studycafe.service;

import lombok.RequiredArgsConstructor;
import nerds.studiousTestProject.studycafe.dto.SearchRequest;
import nerds.studiousTestProject.studycafe.dto.SearchResponse;
import nerds.studiousTestProject.studycafe.repository.StudycafeDslRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Service
@RequiredArgsConstructor
@Transactional
public class StudyCafeService {
    private final StudycafeDslRepository studycafeDslRepository;

    /**
     * 사용자가 정한 필터 및 정렬 조건을 반영하여 알맞는 카페 정보들을 반환하는 메소드
     * @param searchRequest 사용자 검색 요청값
     * @return 검색 결과
     */
    @Transactional(readOnly = true)
    public List<SearchResponse> inquire(SearchRequest searchRequest) {
        String keyword = searchRequest.getKeyword();
        if (keyword.isBlank()) {
            throw new RuntimeException("키워드를 입력해주세요. 키워드는 공백일 수 없습니다.");
        }

        return studycafeDslRepository.searchAll(searchRequest);
    }
}
