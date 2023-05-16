package crypto;
/* trying */
//hello
import java.awt.EventQueue;
import crypto.rsa;
import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.border.TitledBorder;
import java.awt.Color;
import javax.swing.JTextPane;
import javax.swing.JTextField;
import javax.swing.JLabel;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.border.EtchedBorder;
import javax.swing.JButton;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;
import net.miginfocom.swing.MigLayout;
import javax.swing.JTextArea;
import javax.swing.JScrollPane;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.swing.JOptionPane;


public class cryptotool {
	private SecretKey key_aes;

	private JFrame frame;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					cryptotool window = new cryptotool();
					window.frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public cryptotool() {
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frame = new JFrame();
		frame.setBounds(100, 100, 506, 556);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		frame.getContentPane().add(tabbedPane, BorderLayout.NORTH);
		
		JPanel rsa = new JPanel();
		tabbedPane.addTab("RSA", null, rsa, null);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Settings", TitledBorder.LEFT, TitledBorder.TOP, null, new Color(0, 0, 0)));
		
		JPanel panel_1_1 = new JPanel();
		panel_1_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Encrypt / Decrypt", TitledBorder.LEFT, TitledBorder.TOP, null, Color.BLACK));
		GroupLayout gl_rsa = new GroupLayout(rsa);
		gl_rsa.setHorizontalGroup(
			gl_rsa.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_rsa.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_rsa.createParallelGroup(Alignment.TRAILING)
						.addComponent(panel_1_1, Alignment.LEADING, 0, 0, Short.MAX_VALUE)
						.addComponent(panel_2, Alignment.LEADING, GroupLayout.PREFERRED_SIZE, 467, GroupLayout.PREFERRED_SIZE))
					.addContainerGap(10, Short.MAX_VALUE))
		);
		gl_rsa.setVerticalGroup(
			gl_rsa.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_rsa.createSequentialGroup()
					.addContainerGap()
					.addComponent(panel_2, GroupLayout.PREFERRED_SIZE, 219, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(panel_1_1, GroupLayout.PREFERRED_SIZE, 254, Short.MAX_VALUE)
					.addContainerGap())
		);
		
		JLabel lblNewLabel_2 = new JLabel("Cipher / Plain Text");
		
		JTextArea input = new JTextArea();

		JLabel lblNewLabel = new JLabel("Private Key");
		JLabel lblNewLabel_1 = new JLabel("Public Key");
		
		JTextArea privatekey_input = new JTextArea();
		JTextArea publickey_input = new JTextArea();

		JButton generate = new JButton("Generate Key Pairs");
		generate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e){
				try{
					KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
					keyPairGenerator.initialize(1024); // Specify the key size
					KeyPair keyPair = keyPairGenerator.generateKeyPair();
					String publicKey = Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded());
					String privateKey = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());
					privatekey_input.setText(privateKey);
					publickey_input.setText(publicKey);
				}catch(NoSuchAlgorithmException ex){
					ex.printStackTrace();
				}
			}

			
		});

		JTextArea output_rsa = new JTextArea();

		JButton encrypt_rsa_button = new JButton("Encrypt");
		encrypt_rsa_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try{

					// get the plaint text and public key from the gui
					String plaintextRSA = input.getText();
					String publicKeyString = publickey_input.getText();

					// Decode the base64- encoded public key
					byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
					PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

					// create a cipher object and initialize it for encryption
					Cipher cipher = Cipher.getInstance("RSA");
					cipher.init(cipher.ENCRYPT_MODE,publicKey);

					// encrypt the plainttext and encoded it in base64 format
					byte[] ciphertextBytes = cipher.doFinal(plaintextRSA.getBytes());
					String ciphertext = Base64.getEncoder().encodeToString(ciphertextBytes);

					// dispplay the ciphertext in the output
					output_rsa.setText(ciphertext);
				} catch(Exception ex){
					ex.printStackTrace();
				}
			}
		});
		
		JButton clear_settings1 = new JButton("Clear");
		clear_settings1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e){
				privatekey_input.setText("");
				publickey_input.setText("");
			}
			
		});
		
		
		 

		
		JButton decrypt_rsa_button = new JButton("Decrypt");
		decrypt_rsa_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try{

					// get the cipher text and private key from the gui
					String ciphertext = input.getText();
					String privateKeyString= privatekey_input.getText();

					// decode the base64 private key
					byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
					PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

					//create a cipher object and initialize it for decryption
					Cipher cipher = Cipher.getInstance("RSA");
					cipher.init(Cipher.DECRYPT_MODE, privateKey);

					// Decode the Base64-encoded ciphertext and decrypt it
					byte[] ciphertextBytes = Base64.getDecoder().decode(ciphertext);
					byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);

					// Convert the decrypted bytes to a string and set it in the decrypted text area
					String decryptedText = new String(decryptedBytes);
					output_rsa.setText(decryptedText);

				}catch(Exception ex){
					ex.printStackTrace();
				}
			}
		});
		
		JButton Clear = new JButton("Clear");
		Clear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				input.setText("");
				output_rsa.setText("");
			}
		});
		
		JLabel lblNewLabel_3 = new JLabel("Output");
		
		GroupLayout gl_panel_1_1 = new GroupLayout(panel_1_1);
		gl_panel_1_1.setHorizontalGroup(
			gl_panel_1_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1_1.createSequentialGroup()
					.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(input, GroupLayout.DEFAULT_SIZE, 435, Short.MAX_VALUE))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addGap(184)
							.addComponent(Clear))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
								.addComponent(output_rsa, GroupLayout.PREFERRED_SIZE, 435, GroupLayout.PREFERRED_SIZE)
								.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
									.addComponent(lblNewLabel_2)
									.addGroup(gl_panel_1_1.createSequentialGroup()
										.addComponent(lblNewLabel_3, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
										.addPreferredGap(ComponentPlacement.RELATED, 98, Short.MAX_VALUE)
										.addComponent(encrypt_rsa_button)
										.addGap(18)
										.addComponent(decrypt_rsa_button)
										.addGap(140))))))
					.addContainerGap())
		);
		gl_panel_1_1.setVerticalGroup(
			gl_panel_1_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1_1.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_2)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(input, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addGap(18)
							.addComponent(lblNewLabel_3))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addGroup(gl_panel_1_1.createParallelGroup(Alignment.BASELINE)
								.addComponent(encrypt_rsa_button)
								.addComponent(decrypt_rsa_button))))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(output_rsa, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGap(18)
					.addComponent(Clear)
					.addGap(25))
		);
		panel_1_1.setLayout(gl_panel_1_1);
		
	
		
		JScrollPane scrollPane = new JScrollPane();
		GroupLayout gl_panel_2 = new GroupLayout(panel_2);
		gl_panel_2.setHorizontalGroup(
			gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_2.createSequentialGroup()
					.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_2.createSequentialGroup()
							.addContainerGap()
							.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
								.addComponent(lblNewLabel_1, GroupLayout.PREFERRED_SIZE, 62, GroupLayout.PREFERRED_SIZE)
								.addComponent(lblNewLabel))
							.addGap(10)
								.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
								.addComponent(publickey_input, GroupLayout.DEFAULT_SIZE, 363, Short.MAX_VALUE)
								.addComponent(privatekey_input, GroupLayout.DEFAULT_SIZE, 363, Short.MAX_VALUE)))
						.addGroup(gl_panel_2.createSequentialGroup()
							.addGap(100)
							.addComponent(generate)
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(clear_settings1, GroupLayout.PREFERRED_SIZE, 114, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap())
		);
		gl_panel_2.setVerticalGroup(
			gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_2.createSequentialGroup()
					.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.TRAILING, false)
						.addGroup(gl_panel_2.createSequentialGroup()
							.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
							.addComponent(lblNewLabel)
								.addComponent(privatekey_input, GroupLayout.PREFERRED_SIZE, 54, GroupLayout.PREFERRED_SIZE))
							.addGap(12))
						.addGroup(gl_panel_2.createSequentialGroup()
							.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addGap(35)))
					.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
						.addComponent(lblNewLabel_1)
						.addComponent(publickey_input, GroupLayout.PREFERRED_SIZE, 54, GroupLayout.PREFERRED_SIZE))
					.addGap(26)
							.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
								.addComponent(generate)
								.addComponent(clear_settings1))
					.addGap(30))
		);
		panel_2.setLayout(gl_panel_2);
		rsa.setLayout(gl_rsa);
		
		JPanel aes = new JPanel();
		tabbedPane.addTab(" AES", null, aes, null);
		
		JPanel panel = new JPanel();
		panel.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Settings", TitledBorder.LEFT, TitledBorder.TOP, null, new Color(0, 0, 0)));
		
		JPanel panel_1_1_1 = new JPanel();
		panel_1_1_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Encrypt / Decrypt", TitledBorder.LEFT, TitledBorder.TOP, null, Color.BLACK));
		
		JTextArea input_aes = new JTextArea();
		
		JButton Clear_1 = new JButton("Clear");
		
		
		JTextArea output_aes = new JTextArea();
		Clear_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				output_aes.setText("");
			}
		});
		
		JLabel lblNewLabel_2_1 = new JLabel("Cipher / Plain Text");
		
		JLabel lblNewLabel_3_1 = new JLabel("Output");
		
		JButton encrypt_aes_button = new JButton("Encrypt");
encrypt_aes_button.addActionListener(new ActionListener() {
    public void actionPerformed(ActionEvent e) {
        try {
            // Get the plaintext from the GUI input
            byte[] plaintext = input_aes.getText().getBytes();

            // Call the encrypt() function with the plaintext and the key
            byte[] ciphertext = encrypt_aes(plaintext, key_aes);
			String base64Ciphertext = Base64.getEncoder().encodeToString(ciphertext);

            output_aes.setText(base64Ciphertext);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

	// The encrypt() function
byte[] encrypt_aes(byte[] plaintext, SecretKey key_aes) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key_aes);
    return cipher.doFinal(plaintext);
}
});



		

		JButton decrypt_aes_button = new JButton("Decrypt");
		decrypt_aes_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					// Get the ciphertext from the GUI input
					byte[] ciphertext = Base64.getDecoder().decode(input_aes.getText());
					byte[] decryptedText = decrypt_aes(ciphertext, key_aes);		
					// Call the decrypt_aes() function with the ciphertext and the key

					output_aes.setText(new String(decryptedText));
					// Set the plaintext to the output GUI component
				} catch (Exception ex) {
					ex.printStackTrace();
				}
			}
		
			// The decrypt_aes() function
			byte[] decrypt_aes(byte[] ciphertext, SecretKey key_aes) throws Exception {
				Cipher cipher = Cipher.getInstance("AES");
				cipher.init(Cipher.DECRYPT_MODE, key_aes);
				return cipher.doFinal(ciphertext);
			}
		});

		GroupLayout gl_panel_1_1_1 = new GroupLayout(panel_1_1_1);
		gl_panel_1_1_1.setHorizontalGroup(
			gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
				.addGap(0, 467, Short.MAX_VALUE)
				.addGroup(gl_panel_1_1_1.createSequentialGroup()
					.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(input_aes, GroupLayout.DEFAULT_SIZE, 435, Short.MAX_VALUE))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addGap(184)
							.addComponent(Clear_1))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addContainerGap()
							.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
								.addComponent(output_aes, GroupLayout.PREFERRED_SIZE, 435, GroupLayout.PREFERRED_SIZE)
								.addComponent(lblNewLabel_2_1)
								.addGroup(gl_panel_1_1_1.createSequentialGroup()
									.addComponent(lblNewLabel_3_1, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED, 98, Short.MAX_VALUE)
									.addComponent(encrypt_aes_button)
									.addGap(18)
									.addComponent(decrypt_aes_button)
									.addGap(140)))))
					.addContainerGap())
		);
		gl_panel_1_1_1.setVerticalGroup(
			gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
				.addGap(0, 254, Short.MAX_VALUE)
				.addGroup(gl_panel_1_1_1.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_2_1)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(input_aes, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addGap(18)
							.addComponent(lblNewLabel_3_1))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.BASELINE)
								.addComponent(encrypt_aes_button)
								.addComponent(decrypt_aes_button))))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(output_aes, GroupLayout.PREFERRED_SIZE, 52, GroupLayout.PREFERRED_SIZE)
					.addGap(18)
					.addComponent(Clear_1)
					.addGap(25))
		);
		panel_1_1_1.setLayout(gl_panel_1_1_1);
		GroupLayout gl_aes = new GroupLayout(aes);
		gl_aes.setHorizontalGroup(
			gl_aes.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_aes.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_aes.createParallelGroup(Alignment.LEADING)
						.addComponent(panel, GroupLayout.DEFAULT_SIZE, 467, Short.MAX_VALUE)
						.addComponent(panel_1_1_1, GroupLayout.PREFERRED_SIZE, 467, GroupLayout.PREFERRED_SIZE))
					.addContainerGap())
		);
		gl_aes.setVerticalGroup(
			gl_aes.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_aes.createSequentialGroup()
					.addGap(12)
					.addComponent(panel, GroupLayout.PREFERRED_SIZE, 219, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(panel_1_1_1, GroupLayout.PREFERRED_SIZE, 254, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
		);
		
		JLabel lblNewLabel_4 = new JLabel("Secret Key");
		
		JTextArea textArea = new JTextArea();
		
		JButton generate_aes_button = new JButton("Generate Key");
generate_aes_button.addActionListener(new ActionListener() {
    public void actionPerformed(ActionEvent e) {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128, new SecureRandom());
            key_aes = keyGenerator.generateKey();
            String keyString = Base64.getEncoder().encodeToString(key_aes.getEncoded());
			textArea.setText(keyString);
        } catch (NoSuchAlgorithmException ex) {
            ex.printStackTrace();
        }
    }
});

		
		
		JButton btnNewButton = new JButton("Clear");
		btnNewButton.addActionListener(new ActionListener() {
    public void actionPerformed(ActionEvent e) {
        output_aes.setText(" hi");
    }
});
		GroupLayout gl_panel = new GroupLayout(panel);
		gl_panel.setHorizontalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_4)
					.addGap(28)
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(51)
							.addComponent(generate_aes_button)
							.addGap(18)
							.addComponent(btnNewButton, GroupLayout.PREFERRED_SIZE, 88, GroupLayout.PREFERRED_SIZE))
						.addComponent(textArea, GroupLayout.PREFERRED_SIZE, 337, GroupLayout.PREFERRED_SIZE))
					.addContainerGap(22, Short.MAX_VALUE))
		);
		gl_panel.setVerticalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(22)
							.addComponent(textArea, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE))
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(39)
							.addComponent(lblNewLabel_4)))
					.addGap(48)
					.addGroup(gl_panel.createParallelGroup(Alignment.BASELINE)
						.addComponent(generate_aes_button)
						.addComponent(btnNewButton))
					.addContainerGap(69, Short.MAX_VALUE))
		);
		panel.setLayout(gl_panel);
		aes.setLayout(gl_aes);
	}


}


