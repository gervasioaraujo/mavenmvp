package com.liquido.mvp;

import com.liquido.mvp.service.RedebanService;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

@Import({
        RedebanService.class
})
@Configuration
public class MvpConfiguration {
}
