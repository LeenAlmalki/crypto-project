package crypto;
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
import javax.swing.ScrollPaneConstants;
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
import javax.swing.JScrollBar;
import java.awt.ScrollPane;


public class cryptotool {
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
		frame.setBounds(100, 100, 513, 556);
		frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JTabbedPane tabbedPane = new JTabbedPane(JTabbedPane.TOP);
		frame.getContentPane().add(tabbedPane, BorderLayout.NORTH);
		
		/**
		 * RSA Panel
		 */
		JPanel rsa = new JPanel();
		tabbedPane.addTab("RSA", null, rsa, null);
		
		JPanel panel_2 = new JPanel();
		panel_2.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Settings", TitledBorder.LEFT, TitledBorder.TOP, null, new Color(0, 0, 0)));
		
		JPanel panel_1_1 = new JPanel();
		panel_1_1.setBorder(new TitledBorder(new EtchedBorder(EtchedBorder.LOWERED, new Color(255, 255, 255), new Color(160, 160, 160)), "Encrypt / Decrypt", TitledBorder.LEFT, TitledBorder.TOP, null, Color.BLACK));
		GroupLayout gl_rsa = new GroupLayout(rsa);
		gl_rsa.setHorizontalGroup(
			gl_rsa.createParallelGroup(Alignment.LEADING)
				.addGroup(Alignment.TRAILING, gl_rsa.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_rsa.createParallelGroup(Alignment.TRAILING)
						.addComponent(panel_1_1, Alignment.LEADING, 0, 0, Short.MAX_VALUE)
						.addComponent(panel_2, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 464, Short.MAX_VALUE))
					.addGap(26))
		);
		gl_rsa.setVerticalGroup(
			gl_rsa.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_rsa.createSequentialGroup()
					.addContainerGap()
					.addComponent(panel_2, GroupLayout.PREFERRED_SIZE, 219, GroupLayout.PREFERRED_SIZE)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(panel_1_1, GroupLayout.PREFERRED_SIZE, 248, GroupLayout.PREFERRED_SIZE)
					.addContainerGap(18, Short.MAX_VALUE))
		);
		
		JLabel lblNewLabel_2 = new JLabel("Cipher / Plain Text");
		JTextArea privatekey_input = new JTextArea();
		privatekey_input.setLineWrap(true);
		JTextArea publickey_input = new JTextArea();
		publickey_input.setLineWrap(true);
		
		JTextArea input_rsa = new JTextArea();
		input_rsa.setLineWrap(true);
		JTextArea output_rsa = new JTextArea();
		output_rsa.setLineWrap(true);
		
		JLabel lblNewLabel = new JLabel("Private Key");
		JLabel lblNewLabel_1 = new JLabel("Public Key");
		
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

		JButton encrypt_rsa_button = new JButton("Encrypt");
		encrypt_rsa_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try{

					// get the plaint text and public key from the gui
					String plaintextRSA = input_rsa.getText();
					String publicKeyString = publickey_input.getText();

					// Decode the base64- encoded public key
					byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyString);
					PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));

					// create a cipher object and initialize it for encryption
					Cipher cipher_rsa = Cipher.getInstance("RSA");
					cipher_rsa.init(cipher_rsa.ENCRYPT_MODE,publicKey);

					// encrypt the plainttext and encoded it in base64 format
					byte[] ciphertextBytes_rsa = cipher_rsa.doFinal(plaintextRSA.getBytes());
					String ciphertext_rsa = Base64.getEncoder().encodeToString(ciphertextBytes_rsa);

					// dispplay the ciphertext in the output
					output_rsa.setText(ciphertext_rsa);
				} catch(Exception ex){
					JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
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
					String ciphertext_rsa = input_rsa.getText();
					String privateKeyString= privatekey_input.getText();

					// decode the base64 private key
					byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyString);
					PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

					//create a cipher object and initialize it for decryption
					Cipher cipher_rsa = Cipher.getInstance("RSA");
					cipher_rsa.init(Cipher.DECRYPT_MODE, privateKey);

					// Decode the Base64-encoded ciphertext and decrypt it
					byte[] ciphertextBytes_rsa = Base64.getDecoder().decode(ciphertext_rsa);
					byte[] decryptedBytes_rsa = cipher_rsa.doFinal(ciphertextBytes_rsa);

					// Convert the decrypted bytes to a string and set it in the decrypted text area
					String decryptedText_rsa = new String(decryptedBytes_rsa);
					output_rsa.setText(decryptedText_rsa);

				}catch(Exception ex){
					JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
			        
				}
			}
		});
		
		JButton Clear = new JButton("Clear");
		Clear.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				input_rsa.setText("");
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
							.addGap(143)
							.addComponent(encrypt_rsa_button)
							.addGap(18)
							.addComponent(decrypt_rsa_button))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(lblNewLabel_3, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(lblNewLabel_2))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(input_rsa, GroupLayout.DEFAULT_SIZE, 435, Short.MAX_VALUE))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addGap(193)
							.addComponent(Clear))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(output_rsa, GroupLayout.PREFERRED_SIZE, 435, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap())
		);
		gl_panel_1_1.setVerticalGroup(
			gl_panel_1_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1_1.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_2)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(input_rsa, GroupLayout.PREFERRED_SIZE, 50, GroupLayout.PREFERRED_SIZE)
					.addGroup(gl_panel_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addGap(14)
							.addComponent(lblNewLabel_3)
							.addGap(2))
						.addGroup(gl_panel_1_1.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(gl_panel_1_1.createParallelGroup(Alignment.BASELINE)
								.addComponent(encrypt_rsa_button)
								.addComponent(decrypt_rsa_button))))
					.addPreferredGap(ComponentPlacement.UNRELATED)
					.addComponent(output_rsa, GroupLayout.PREFERRED_SIZE, 50, GroupLayout.PREFERRED_SIZE)
					.addGap(12)
					.addComponent(Clear)
					.addGap(45))
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
							.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
								.addComponent(publickey_input, GroupLayout.PREFERRED_SIZE, 360, GroupLayout.PREFERRED_SIZE)
								.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
								.addComponent(privatekey_input, GroupLayout.PREFERRED_SIZE, 360, GroupLayout.PREFERRED_SIZE)))
						.addGroup(gl_panel_2.createSequentialGroup()
							.addGap(103)
							.addComponent(generate)
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(clear_settings1, GroupLayout.PREFERRED_SIZE, 114, GroupLayout.PREFERRED_SIZE)))
					.addContainerGap(24, Short.MAX_VALUE))
		);
		gl_panel_2.setVerticalGroup(
			gl_panel_2.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_2.createSequentialGroup()
					.addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
					.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
						.addComponent(privatekey_input, Alignment.TRAILING, GroupLayout.PREFERRED_SIZE, 59, GroupLayout.PREFERRED_SIZE)
						.addGroup(Alignment.TRAILING, gl_panel_2.createSequentialGroup()
							.addComponent(lblNewLabel)
							.addGap(22)))
					.addGroup(gl_panel_2.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_2.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.RELATED, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
							.addComponent(scrollPane, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.RELATED)
							.addComponent(publickey_input, GroupLayout.PREFERRED_SIZE, 59, GroupLayout.PREFERRED_SIZE)
							.addGap(18)
							.addGroup(gl_panel_2.createParallelGroup(Alignment.BASELINE)
								.addComponent(generate)
								.addComponent(clear_settings1))
							.addGap(57))
						.addGroup(gl_panel_2.createSequentialGroup()
							.addGap(31)
							.addComponent(lblNewLabel_1)
							.addContainerGap())))
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
		input_aes.setLineWrap(true);
		
		JTextArea output_aes = new JTextArea();
		output_aes.setLineWrap(true);

		JButton Clear_1 = new JButton("Clear");
		Clear_1.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				output_aes.setText("");
			}
		});
		
		JLabel lblNewLabel_2_1 = new JLabel("Cipher / Plain Text");
		
		JLabel lblNewLabel_3_1 = new JLabel("Output");
		private SecretKey key_aes;

		JButton encrypt_aes_button = new JButton("Encrypt");
		encrypt_aes_button.addActionListener(new ActionListener() {
    	public void actionPerformed(ActionEvent e) {
			try {
				// Get the plaintext from the GUI input
				byte[] plaintext_aes = input_aes.getText().getBytes();

				// Call the encrypt() function with the plaintext and the key
				byte[] ciphertext_aes = encrypt_aes(plaintext_aes, key_aes);
				String base64Ciphertext_aes = Base64.getEncoder().encodeToString(ciphertext_aes);

				output_aes.setText(base64Ciphertext_aes);
			} catch (Exception ex) {
				JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
			}
		}

			// The encrypt() function
		byte[] encrypt_aes(byte[] plaintext_aes, SecretKey key_aes) throws Exception {
			Cipher cipher_aes = Cipher.getInstance("AES");
			cipher_aes.init(Cipher.ENCRYPT_MODE, key_aes);
			return cipher_aes.doFinal(plaintext_aes);
		}
		});



		

		JButton decrypt_aes_button = new JButton("Decrypt");
		decrypt_aes_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					// Get the ciphertext from the GUI input
					byte[] ciphertext_aes = Base64.getDecoder().decode(input_aes.getText());
					byte[] decryptedText_aes = decrypt_aes(ciphertext_aes, key_aes);		
					// Call the decrypt_aes() function with the ciphertext and the key

					output_aes.setText(new String(decryptedText_aes));
					// Set the plaintext to the output GUI component
				} catch (Exception ex) {
					JOptionPane.showMessageDialog(null, "Error: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
				}
			}
		
			// The decrypt_aes() function
			byte[] decrypt_aes(byte[] ciphertext_aes, SecretKey key_aes) throws Exception {
				Cipher cipher_aes = Cipher.getInstance("AES");
				cipher_aes.init(Cipher.DECRYPT_MODE, key_aes);
				return cipher_aes.doFinal(ciphertext_aes);
			}
		});
		
		

		GroupLayout gl_panel_1_1_1 = new GroupLayout(panel_1_1_1);
		gl_panel_1_1_1.setHorizontalGroup(
			gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1_1_1.createSequentialGroup()
					.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addContainerGap()
							.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
								.addComponent(lblNewLabel_2_1)
								.addGroup(gl_panel_1_1_1.createSequentialGroup()
									.addComponent(lblNewLabel_3_1, GroupLayout.PREFERRED_SIZE, 45, GroupLayout.PREFERRED_SIZE)
									.addPreferredGap(ComponentPlacement.RELATED, 107, Short.MAX_VALUE)
									.addComponent(encrypt_aes_button)
									.addGap(18)
									.addComponent(decrypt_aes_button)
									.addGap(148))))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(input_aes, GroupLayout.PREFERRED_SIZE, 435, GroupLayout.PREFERRED_SIZE))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addContainerGap()
							.addComponent(output_aes, GroupLayout.PREFERRED_SIZE, 435, GroupLayout.PREFERRED_SIZE))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addGap(187)
							.addComponent(Clear_1)))
					.addContainerGap())
		);
		gl_panel_1_1_1.setVerticalGroup(
			gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel_1_1_1.createSequentialGroup()
					.addContainerGap()
					.addComponent(lblNewLabel_2_1)
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(input_aes, GroupLayout.PREFERRED_SIZE, 50, GroupLayout.PREFERRED_SIZE)
					.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addGap(20)
							.addComponent(lblNewLabel_3_1))
						.addGroup(gl_panel_1_1_1.createSequentialGroup()
							.addPreferredGap(ComponentPlacement.RELATED)
							.addGroup(gl_panel_1_1_1.createParallelGroup(Alignment.BASELINE)
								.addComponent(decrypt_aes_button)
								.addComponent(encrypt_aes_button))))
					.addPreferredGap(ComponentPlacement.RELATED)
					.addComponent(output_aes, GroupLayout.PREFERRED_SIZE, 50, GroupLayout.PREFERRED_SIZE)
					.addGap(18)
					.addComponent(Clear_1)
					.addGap(35))
		);
		panel_1_1_1.setLayout(gl_panel_1_1_1);
		GroupLayout gl_aes = new GroupLayout(aes);
		gl_aes.setHorizontalGroup(
			gl_aes.createParallelGroup(Alignment.TRAILING)
				.addGroup(gl_aes.createSequentialGroup()
					.addContainerGap()
					.addGroup(gl_aes.createParallelGroup(Alignment.TRAILING)
						.addComponent(panel_1_1_1, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE)
						.addComponent(panel, Alignment.LEADING, GroupLayout.DEFAULT_SIZE, 474, Short.MAX_VALUE))
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
		
		JTextArea textArea_key_aes = new JTextArea();
		
		JButton generate_aes_button = new JButton("Generate Key");
		generate_aes_button.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
        try {
            KeyGenerator keyGenerator_aes = KeyGenerator.getInstance("AES");
            keyGenerator_aes.init(128, new SecureRandom());
            key_aes = keyGenerator_aes.generateKey();
            String keyString_aes = Base64.getEncoder().encodeToString(key_aes.getEncoded());
			textArea_key_aes.setText(keyString_aes);
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
						.addComponent(textArea_key_aes, GroupLayout.PREFERRED_SIZE, 337, GroupLayout.PREFERRED_SIZE))
					.addContainerGap(22, Short.MAX_VALUE))
		);
		gl_panel.setVerticalGroup(
			gl_panel.createParallelGroup(Alignment.LEADING)
				.addGroup(gl_panel.createSequentialGroup()
					.addGroup(gl_panel.createParallelGroup(Alignment.LEADING)
						.addGroup(gl_panel.createSequentialGroup()
							.addGap(22)
							.addComponent(textArea_key_aes, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE))
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


