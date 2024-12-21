package com.rafo.app.ms_security.controller;

import com.rafo.app.ms_security.dto.AuthRequest;
import com.rafo.app.ms_security.dto.AuthResponse;
import com.rafo.app.ms_security.model.Role;
import com.rafo.app.ms_security.model.User;
import com.rafo.app.ms_security.repository.UserRepository;
import com.rafo.app.ms_security.security.JwtTokenProvider;
import com.rafo.app.ms_security.util.Constants;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/users")
public class UserController {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public UserController(UserRepository userRepository, JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.passwordEncoder = new BCryptPasswordEncoder(); // Instancia del codificador
    }

    @GetMapping
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }

    @PostMapping
    public User createUser(@RequestBody User user) {
        // Cifrar la contraseña antes de guardar
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    @GetMapping("/{username}")
    public ResponseEntity<User> getUserByUsername(@PathVariable String username) {
        Optional<User> user = userRepository.findByUsername(username);

        if (user.isPresent()) {
            return ResponseEntity.ok(user.get());
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/authenticate")
    public ResponseEntity<?> authenticate(@RequestBody AuthRequest authRequest) {
        Optional<User> userOpt = userRepository.findByUsername(authRequest.getUsername());

        if (userOpt.isPresent()) {
            User user = userOpt.get();
            if (passwordEncoder.matches(authRequest.getPassword(), user.getPassword())) {
                String token = jwtTokenProvider.generateToken(user.getUsername(), user.getRole().name());
                return ResponseEntity.ok(new AuthResponse(token));
            }
        }

        return ResponseEntity.status(401).body(Constants.INVALID_USER_OR_PASSWORD);
    }

}
