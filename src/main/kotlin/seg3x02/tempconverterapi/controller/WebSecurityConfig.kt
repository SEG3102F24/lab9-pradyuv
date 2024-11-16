package seg3x02.tempconverterapi.security

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain

@Configuration
@EnableWebSecurity
class SecurityConfiguration {

    @Bean
    fun configureUsers(): UserDetailsService {
        val firstUser: UserDetails = User.builder()
            .username("user1")
            .password(encodePassword().encode("pass1"))
            .roles("USER")
            .build()
        
        val secondUser: UserDetails = User.builder()
            .username("user2")
            .password(encodePassword().encode("pass2"))
            .roles("USER")
            .build()

        return InMemoryUserDetailsManager(listOf(firstUser, secondUser))
    }

    @Bean
    fun ignoreWebPaths(): WebSecurityCustomizer {
        return WebSecurityCustomizer { webSecurity ->
            webSecurity.ignoring().requestMatchers(
                "/assets/**", "/media/**", "/styles/**", "/scripts/**", "/images/**", "/libs/**", "/fonts/**"
            )
        }
    }

    @Bean
    fun encodePassword(): BCryptPasswordEncoder {
        return BCryptPasswordEncoder()
    }
}
