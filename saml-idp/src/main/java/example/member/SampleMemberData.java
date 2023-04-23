package example.member;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class SampleMemberData implements CommandLineRunner{
    @Autowired
    private MemberRepository memberRepository;

    @Override
    public void run(String... args) throws Exception {
        for(int i=1; i<=5; i++) {
        	memberRepository.save(new Member("abc"+i, i+"","abc"+i+"@gmail.com", "ADMIN"));
        }
    }
}
