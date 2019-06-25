package sp;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class CASClientController {

    @RequestMapping("/casclient")
    public String contextInfo(Model model) {

        return "casclient";
    }
    
}